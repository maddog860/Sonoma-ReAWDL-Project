//
//  AirportItlwmV2.cpp
//  AirportItlwm-Sonoma
//
//  Created by qcwap on 2023/6/27.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#include "AirportItlwmV2.hpp"
#include <sys/_netstat.h>
#include <crypto/sha1.h>
#include <net80211/ieee80211_priv.h>
#include <net80211/ieee80211_var.h>

#include "AirportItlwmSkywalkInterface.hpp"
#include "AirportItlwmAWDLInterface.hpp"

extern "C"
IO80211VirtualInterface *
AirportItlwmCreateVirtualInterfaceBridge(
    void *controllerOpaque,
    ether_addr *ether,
    UInt role
);

#include "IOPCIEDeviceWrapper.hpp"

#define super IO80211Controller
OSDefineMetaClassAndStructors(AirportItlwm, IO80211Controller);

/*
 * Experimental Intel-firmware -> Apple AWDL event bridge.
 *
 * V2 does not keep the AWDL VIF in a controller member, so cache the
 * successfully attached AWDL protocol object here instead.
 */
static AirportItlwm *gAirplayAWDLController = nullptr;
static AirportItlwmAWDLInterface *gAirplayAWDLInterface = nullptr;

struct ether_addr gAirplayAWDLAddress = {};
bool gAirplayAWDLAddressValid = false;


/*
 * Diagnostic-only Sonoma V2 TX entry counters.
 */
static UInt32 gAirplayV2RequestPacketTxHits = 0;
static UInt32 gAirplayV2RequestPacketTxAWDLHits = 0;
static UInt32 gAirplayV2BPFOutputPacketHits = 0;


/*
 * KGP virtual-interface lifecycle behavior.
 *
 * Keep Apple's V2 virtual interface machinery, but explicitly bring the
 * AWDL/P2P interface into the same enabled/link-up state that KGP uses.
 */

SInt32
AirportItlwm::enableVirtualInterface(
    IO80211VirtualInterface *interface)
{
    SInt32 ret =
        super::enableVirtualInterface(interface);

    if (ret == 0 && interface != nullptr) {

        interface->setEnabledBySystem(true);

        interface->setLinkState(
            kIO80211NetworkLinkUp,
            0
        );

        interface->postMessage(
            APPLE80211_M_LINK_CHANGED,
            nullptr,
            0,
            false
        );

        setProperty(
            "AIRPLAYKGPEnableVIFSuccess",
            (unsigned long long)1,
            8
        );

        setProperty(
            "AIRPLAYKGPEnableVIFRole",
            (unsigned long long)interface->getInterfaceRole(),
            32
        );
    }

    return ret;
}


SInt32
AirportItlwm::disableVirtualInterface(
    IO80211VirtualInterface *interface)
{
    SInt32 ret =
        super::disableVirtualInterface(interface);

    if (ret == 0 && interface != nullptr) {

        interface->setLinkState(
            kIO80211NetworkLinkDown,
            0
        );

        interface->postMessage(
            APPLE80211_M_LINK_CHANGED,
            nullptr,
            0,
            false
        );
    }

    return ret;
}

void
AirportItlwm::requestPacketTx(void *object, UInt arg)
{
    UInt32 hits = __atomic_add_fetch(
        &gAirplayV2RequestPacketTxHits,
        (UInt32)1,
        __ATOMIC_RELAXED
    );

    setProperty(
        "AIRPLAYV2RequestPacketTxHits",
        (unsigned long long)hits,
        32
    );

    IO80211VirtualInterface *interface =
        OSDynamicCast(IO80211VirtualInterface, (OSObject *)object);

    if (interface != nullptr) {
        UInt32 role = interface->getInterfaceRole();

        setProperty(
            "AIRPLAYV2RequestPacketTxLastRole",
            (unsigned long long)role,
            32
        );

        if (role == APPLE80211_VIF_AWDL) {
            UInt32 awdlHits = __atomic_add_fetch(
                &gAirplayV2RequestPacketTxAWDLHits,
                (UInt32)1,
                __ATOMIC_RELAXED
            );

            setProperty(
                "AIRPLAYV2RequestPacketTxAWDLHits",
                (unsigned long long)awdlHits,
                32
            );
        }
    }

    super::requestPacketTx(object, arg);
}

int
AirportItlwm::bpfOutputPacket(OSObject *object, UInt dltType, mbuf_t m)
{
    UInt32 hits = __atomic_add_fetch(
        &gAirplayV2BPFOutputPacketHits,
        (UInt32)1,
        __ATOMIC_RELAXED
    );

    setProperty(
        "AIRPLAYV2BPFOutputPacketHits",
        (unsigned long long)hits,
        32
    );

    setProperty(
        "AIRPLAYV2BPFOutputPacketLastDLT",
        (unsigned long long)dltType,
        32
    );

    return super::bpfOutputPacket(object, dltType, m);
}

/*
 * Sonoma event 41 payload.
 *
 * Native Broadcom sends exactly 0x24 bytes:
 *
 *   +0x00  AW number
 *   +0x04  state
 *   +0x08  master[6]
 *   +0x0e  topMaster[6]
 *   +0x14  firmware AW-start time
 *   +0x18  apple80211_channel
 */
struct AirplayAWStartPayload
{
    UInt32 awNumber;
    UInt32 state;
    UInt8 master[6];
    UInt8 topMaster[6];
    UInt32 fwAwStartTime;
    struct apple80211_channel channel;
};

static_assert(
    sizeof(AirplayAWStartPayload) == 0x24,
    "AW start payload must be 36 bytes"
);

static UInt32 gAirplayAWNumber = 0;

/* AWPROBE-20261015: read-only replica of IO80211's sanityCheckAWStart() */
extern "C" bool AirportItlwmAWDLScheduleSlot(UInt32, UInt32 *, UInt32 *, UInt32 *, UInt32 *, UInt32 *);
static volatile UInt32 gAWProbeInCadence = 0;
static volatile UInt32 gAWMatchAligned = 0, gAWMatchSkipTotal = 0, gAWMatchNoSlot = 0, gAWMatchOff = 0;
static volatile UInt32 gAWProbeReports = 0, gAWProbeNoSched = 0, gAWProbeMatch = 0;
static volatile UInt32 gAWProbeChanMismatch = 0, gAWProbeFlagMismatch = 0, gAWProbeBothZero = 0;
static volatile UInt32 gAWProbeCadenceReports = 0, gAWProbeCadenceMismatch = 0;
static volatile UInt32 gAWProbeFwReports = 0, gAWProbeFwMismatch = 0;
static volatile UInt32 gAWProbeFirstMismatchSlot = 0xffff, gAWProbeFirstMismatchExpChan = 0;
static volatile UInt32 gAWProbeFirstMismatchExpFlags = 0, gAWProbeFirstMismatchRepChan = 0;

/*
 * AWSTART41B: Sonoma 14.x IO80211Family dispatches the native AW-start event as 41.
 * Event 42 (APPLE80211_M_AWDL_AVAILABILITY_WINDOW_START in our header) is accepted
 * but never counted as an AW start ("Did not get AW start event").
 */
static const UInt32 kAirplayAWStartNativeEvent = 41U;

/*
 * Bounded AW-start cadence experiment.
 *
 * A genuine Intel P2P START arms 30 watchdog ticks.
 * The existing watchdog runs every 1000 ms.
 */
static volatile UInt32 gAirplayAWStartCadenceBudget = 0;
static volatile UInt32 gAirplayAWStartCadenceCount = 0;

/*
 * Fresh monotonic bridge telemetry.
 * Unlike the old boolean breadcrumbs, these prove whether a NEW
 * Intel START reaches this function during the current boot.
 */
static volatile UInt32 gAirplayAWStartFunctionEntries = 0;
static volatile UInt32 gAirplayAWStartReportSuccesses = 0;

static volatile UInt32 gAirplayAWStartLastFirmwareTime = 0;
static volatile UInt32 gAirplayAWStartLastChannel = 6;

extern "C" IOReturn
AirportItlwmReportAWDLStart(
    IOEthernetController *controller,
    UInt32 firmwareTime,
    UInt32 channel
)
{
    AirportItlwm *airport =
        OSDynamicCast(AirportItlwm, controller);

    if (airport != nullptr) {
        gAirplayAWStartFunctionEntries++;

        airport->setProperty(
            "AIRPLAYAWStartFunctionEntries",
            (unsigned long long)gAirplayAWStartFunctionEntries,
            32
        );

        airport->setProperty(
            "AIRPLAYAWStartFunctionLastFirmwareTime",
            (unsigned long long)firmwareTime,
            32
        );

        airport->setProperty(
            "AIRPLAYAWStartFunctionLastChannel",
            (unsigned long long)channel,
            32
        );
    }

    if (airport == nullptr ||
        airport->fSonomaAWDLInterface == nullptr) {
        return kIOReturnNotReady;
    }

    AirplayAWStartPayload payload = {};

    gAirplayAWNumber =
        (gAirplayAWNumber + 1) & 0xffff;

    if (gAirplayAWNumber == 0)
        gAirplayAWNumber = 1;

    payload.awNumber = gAirplayAWNumber;

    /* AWMATCH-20261015: land on a slot of macOS's sequence that holds the channel we are on. */
    static int awMatchOff = -1;
    if (awMatchOff < 0) {
        int v = 0;
        awMatchOff = PE_parse_boot_argn("-awdlawmatchoff", &v, sizeof(v)) ? 1 : 0;
        gAWMatchOff = (UInt32)awMatchOff;
    }
    if (!awMatchOff) {
        UInt32 mSlot = 0, mChan = 0, mFlags = 0, mLen = 0, mDup = 0;
        if (AirportItlwmAWDLScheduleSlot(gAirplayAWNumber, &mSlot, &mChan, &mFlags, &mLen, &mDup)) {
            const UInt32 span = mLen * (mDup + 1U);   /* <= 16 * 256 */
            UInt32 k = 0;
            bool found = false;
            for (k = 0; k < span; k++) {
                UInt32 cand = (gAirplayAWNumber + k) & 0xffff;
                if (cand == 0)
                    continue;
                if (AirportItlwmAWDLScheduleSlot(cand, &mSlot, &mChan, &mFlags, &mLen, &mDup) &&
                    mChan == channel) {
                    found = true;
                    break;
                }
            }
            if (found) {
                if (k != 0) {
                    gAirplayAWNumber = (gAirplayAWNumber + k) & 0xffff;
                    if (gAirplayAWNumber == 0)
                        gAirplayAWNumber = 1;
                    gAWMatchSkipTotal += k;
                }
                gAWMatchAligned++;
                payload.awNumber = gAirplayAWNumber;
            } else {
                gAWMatchNoSlot++;
            }
        }
        airport->setProperty("AIRPLAYAWMatchAligned", (unsigned long long)gAWMatchAligned, 32);
        airport->setProperty("AIRPLAYAWMatchSkipTotal", (unsigned long long)gAWMatchSkipTotal, 32);
        airport->setProperty("AIRPLAYAWMatchNoSlot", (unsigned long long)gAWMatchNoSlot, 32);
    }
    airport->setProperty("AIRPLAYAWMatchOff", (unsigned long long)gAWMatchOff, 32);

    /*
     * Broadcom derives this from firmware state.
     * Keep it zero for the first event-path validation.
     */
    payload.state = 0;

    /*
     * IO80211 byte-swaps the native +0x14 field.
     * Intel GP2 is already host-endian here.
     */
    payload.fwAwStartTime =
        __builtin_bswap32(firmwareTime);

    /*
     * Broadcom leaves version/flags zero and fills
     * the control-channel number.
     */
    payload.channel.version = 0;
    payload.channel.channel = channel;
    /* AWMATCH-20261015: band bit like IO80211's own sequence entries (5 GHz = 0x10, 2.4 GHz = 0x8) */
    payload.channel.flags = awMatchOff ? 0 : ((channel != 0 && channel <= 14) ? 0x8U : 0x10U);

    IOLog(
        "AIRPLAY AWDL BRIDGE41-NATIVE: "
        "aw=%u fw=%u channel=%u len=%lu\n",
        payload.awNumber,
        firmwareTime,
        channel,
        (unsigned long)sizeof(payload)
    );

    /*
     * Sonoma IO80211:
     *   42 = AWDL_AVAILABILITY_WINDOW_START
     *
     * Use the Apple80211 definition directly.
     */
    /*
     * Sonoma 14.x IO80211Family native AW-start jump-table event.
     * Deliberately literal: the local Apple80211 header labels 42,
     * but this running Sonoma binary dispatches native AW START on 41.
     */
    airport->setProperty(
        "AIRPLAYAWStartNative41Mode",
        (unsigned long long)1,
        8
    );

    airport->setProperty(
        "AIRPLAYAWStartNativeEvent",
        (unsigned long long)kAirplayAWStartNativeEvent,
        32
    );

    airport->setProperty(
        "AIRPLAYAWStartNativePayloadLength",
        (unsigned long long)sizeof(payload),
        32
    );

    airport->setProperty(
        "AIRPLAYAWStartNative41CadenceEnabled",
        (unsigned long long)1,
        8
    );

    airport->setProperty(
        "AIRPLAYAWStartDirectPostSuppressed",
        (unsigned long long)1,
        8
    );

    {   /* AWPROBE-20261015: compare exactly what IO80211 will compare. Read-only. */
        UInt32 pSlot = 0, pChan = 0, pFlags = 0, pLen = 0, pDup = 0;
        const bool cadence = (gAWProbeInCadence != 0);
        bool mismatch = false;
        gAWProbeReports++;
        if (cadence) gAWProbeCadenceReports++; else gAWProbeFwReports++;
        if (!AirportItlwmAWDLScheduleSlot(payload.awNumber, &pSlot, &pChan, &pFlags, &pLen, &pDup)) {
            gAWProbeNoSched++;
        } else {
            const UInt32 rChan = payload.channel.channel;
            const UInt32 rFlags = payload.channel.flags;
            if (pChan != rChan) {
                gAWProbeChanMismatch++;
                mismatch = true;
            } else if (pChan == 0) {
                gAWProbeBothZero++;
            } else if (((pFlags ^ rFlags) & 0x2018U) != 0) {
                gAWProbeFlagMismatch++;
                mismatch = true;
            } else {
                gAWProbeMatch++;
            }
            if (mismatch) {
                if (cadence) gAWProbeCadenceMismatch++; else gAWProbeFwMismatch++;
                if (gAWProbeFirstMismatchSlot == 0xffff) {
                    gAWProbeFirstMismatchSlot = pSlot;
                    gAWProbeFirstMismatchExpChan = pChan;
                    gAWProbeFirstMismatchExpFlags = pFlags;
                    gAWProbeFirstMismatchRepChan = rChan;
                }
            }
            airport->setProperty("AIRPLAYAWProbeLastAwNumber", (unsigned long long)payload.awNumber, 32);
            airport->setProperty("AIRPLAYAWProbeLastSlot", (unsigned long long)pSlot, 32);
            airport->setProperty("AIRPLAYAWProbeLastExpectChan", (unsigned long long)pChan, 32);
            airport->setProperty("AIRPLAYAWProbeLastExpectFlags", (unsigned long long)pFlags, 32);
            airport->setProperty("AIRPLAYAWProbeLastReportChan", (unsigned long long)rChan, 32);
            airport->setProperty("AIRPLAYAWProbeLastReportFlags", (unsigned long long)rFlags, 32);
            airport->setProperty("AIRPLAYAWProbeSchedLen", (unsigned long long)pLen, 32);
            airport->setProperty("AIRPLAYAWProbeSchedDup", (unsigned long long)pDup, 32);
            airport->setProperty("AIRPLAYAWProbeAwPerSlot", (unsigned long long)(pDup + 1U), 32); /* AWMATCH2 */
        }
        airport->setProperty("AIRPLAYAWProbeReports", (unsigned long long)gAWProbeReports, 32);
        airport->setProperty("AIRPLAYAWProbeNoSched", (unsigned long long)gAWProbeNoSched, 32);
        airport->setProperty("AIRPLAYAWProbeMatch", (unsigned long long)gAWProbeMatch, 32);
        airport->setProperty("AIRPLAYAWProbeChanMismatch", (unsigned long long)gAWProbeChanMismatch, 32);
        airport->setProperty("AIRPLAYAWProbeFlagMismatch", (unsigned long long)gAWProbeFlagMismatch, 32);
        airport->setProperty("AIRPLAYAWProbeBothZero", (unsigned long long)gAWProbeBothZero, 32);
        airport->setProperty("AIRPLAYAWProbeFwReports", (unsigned long long)gAWProbeFwReports, 32);
        airport->setProperty("AIRPLAYAWProbeFwMismatch", (unsigned long long)gAWProbeFwMismatch, 32);
        airport->setProperty("AIRPLAYAWProbeCadenceReports", (unsigned long long)gAWProbeCadenceReports, 32);
        airport->setProperty("AIRPLAYAWProbeCadenceMismatch", (unsigned long long)gAWProbeCadenceMismatch, 32);
        airport->setProperty("AIRPLAYAWProbeFirstMismatchSlot", (unsigned long long)gAWProbeFirstMismatchSlot, 32);
        airport->setProperty("AIRPLAYAWProbeFirstMismatchExpChan", (unsigned long long)gAWProbeFirstMismatchExpChan, 32);
        airport->setProperty("AIRPLAYAWProbeFirstMismatchExpFlags", (unsigned long long)gAWProbeFirstMismatchExpFlags, 32);
        airport->setProperty("AIRPLAYAWProbeFirstMismatchRepChan", (unsigned long long)gAWProbeFirstMismatchRepChan, 32);
    }

    IOReturn result =
        airport->fSonomaAWDLInterface->reportDataPathEvents(
            kAirplayAWStartNativeEvent, /* AWSTART41B (was 42) */
            &payload,
            sizeof(payload),
            false
        );

    airport->setProperty(
        "AIRPLAYAWStartEventSent",
        (unsigned long long)kAirplayAWStartNativeEvent,
        32
    );

    airport->setProperty(
        "AIRPLAYAWStartFunctionLastResult",
        (unsigned long long)(UInt32)result,
        32
    );

    if (result == kIOReturnSuccess) {
        gAirplayAWStartReportSuccesses++;

        airport->setProperty(
            "AIRPLAYAWStartReportSuccesses",
            (unsigned long long)gAirplayAWStartReportSuccesses,
            32
        );

        gAirplayAWStartLastFirmwareTime = firmwareTime;
        gAirplayAWStartLastChannel = channel;

        /*
         * Only the genuine first START arms the bounded cadence.
         * Calls made while the budget is already active do not reset it.
         */
        if (gAirplayAWStartCadenceBudget == 0) {
            gAirplayAWStartCadenceBudget = 30;

            airport->setProperty(
                "AIRPLAYAWStartCadenceArmed",
                (unsigned long long)1,
                8
            );

            airport->setProperty(
                "AIRPLAYAWStartCadenceBudget",
                (unsigned long long)
                    gAirplayAWStartCadenceBudget,
                32
            );
        }
    }


    /*
     * One-shot diagnostic:
     * direct AW START through the VirtualInterface message path.
     */
    static bool post42ProbeDone = false;

    if (false && !post42ProbeDone) {
        post42ProbeDone = true;

        airport->fSonomaAWDLInterface->setProperty(
            "AIRPLAYDirectPost42Probe",
            1,
            8
        );

        airport->fSonomaAWDLInterface->postMessage(
            41U,
            &payload,
            sizeof(payload),
            false
        );
    }

return result;
}
/*
 * RXFEED-20261010: deliver received AWDL action frames to IO80211AWDLPeerManager,
 * mirroring AppleBCMWLANProximityInterface::handleActionFrame_rx (Sonoma 14.8.7).
 * Called from ItlIwx::iwx_rx_frame() (AWDLSKIP block) for AWDL PSF/MIF frames only.
 */
#include <pexpert/pexpert.h>
#include <sys/time.h>

struct AirplayAFRxInfo {
    uint8_t  sa[6];                      /* 0x00 transmitter (peer AWDL) address */
    uint8_t  pad06[6];                   /* 0x06 */
    struct apple80211_channel channel;   /* 0x0c {version 1, channel, flags} */
    uint8_t  pad18[0x10];                /* 0x18 */
    uint32_t rate;                       /* 0x28 */
    int32_t  rssi;                       /* 0x2c dBm, IO80211 checks != 0 */
    uint32_t timestamp;                  /* 0x30 */
    uint8_t  pad34[0x0c];                /* 0x34 */
    uint32_t chainRssiValid;             /* 0x40 */
    int8_t   chainRssi[4];               /* 0x44 */
} __attribute__((packed));
static_assert(sizeof(AirplayAFRxInfo) == 0x48, "RXFEED: AF rx info must be 0x48 bytes");
static_assert(__builtin_offsetof(AirplayAFRxInfo, channel) == 0x0c, "RXFEED: channel @0x0c");
static_assert(__builtin_offsetof(AirplayAFRxInfo, rssi) == 0x2c, "RXFEED: rssi @0x2c");
static_assert(__builtin_offsetof(AirplayAFRxInfo, timestamp) == 0x30, "RXFEED: timestamp @0x30");

static UInt32 gRxFeedCalls = 0;
static UInt32 gRxFeedDelivered = 0;
static UInt32 gRxFeedDisabled = 0;
static UInt32 gRxFeedBadLen = 0;
static UInt32 gRxFeedNoInterface = 0;
static UInt32 gRxFeedNoPeerMgr = 0;
static UInt32 gRxFeedNoPool = 0;
static UInt32 gRxFeedNoBuffer = 0;
static UInt32 gRxFeedCopyFail = 0;
static UInt32 gRxFeedPeerMgrPresent = 0;
static UInt32 gRxFeedPoolPresent = 0;
static UInt32 gRxFeedIfRole = 0;
static UInt32 gRxFeedLastLen = 0;
static UInt32 gRxFeedLastChan = 0;
static UInt32 gRxFeedLastSubtype = 0;
static UInt32 gRxFeedLastRssiAbs = 0;
static UInt32 gRxFeedChan6 = 0;
static UInt32 gRxFeedChan5G = 0;
static struct timeval gRxFeedLastPublish = {};

/* IO80211VirtualInterface ivars (Apple layout, read-only): this+0x110 -> ivars;
 * ivars+0x30 = peer manager used by bpfTapInput, ivars+0x50 = interface role (6 = AWDL). */
static uint8_t *
airplayRxFeedIvars(IO80211VirtualInterface *vif)
{
    return vif ? *(uint8_t **)((uint8_t *)vif + 0x110) : nullptr;
}

/* UMI-DIAG-V1: one coherent, MAC-keyed pre-input snapshot. Observe only.
 * Layout verified against the saved IO80211Family C0EC2288 image (23J520).
 * Uses the same pointers, throttle, and -awdlmodegateoff as MODEGATE.
 * No Apple state writes and no extra private method calls. */
struct AirplayUmiSnapshotV1 {
    UInt32 version, sequence;
    UInt64 uptimeSeconds;
    UInt32 uptimeUsec;
    UInt8 peer[6], peerFound, statePresent;
    UInt32 peerState, options, options2, attempts, msecSinceAwdlOn;
    UInt8 localSupport, localDisabled, localFastDiscovery, peerSupport;
    UInt8 peerFastDiscovery, bothSidesDiscovered, pppDone, waitingOnChain;
    UInt8 reliable, fw240, fw241, reserved[5];
} __attribute__((packed));
static_assert(sizeof(AirplayUmiSnapshotV1) == 64, "UMI snapshot ABI");

#include "PeerCacheNativeV1.inc"

static void
airplayUmiPublishSnapshot(AirportItlwm *airport, void *peerManager, void *managerState,
                          void *peer, const UInt8 *mac)
{
    static volatile UInt32 sequence = 0;
    AirplayUmiSnapshotV1 s = {};
    s.version = 1;
    s.sequence = __sync_add_and_fetch(&sequence, 1);
    struct timeval now; getmicrouptime(&now);
    s.uptimeSeconds = (UInt64)now.tv_sec;
    s.uptimeUsec = (UInt32)now.tv_usec;
    memcpy(s.peer, mac, 6);
    const UInt8 *ms = reinterpret_cast<const UInt8 *>(managerState);
    s.localSupport = ms[0x3f8c];
    s.localDisabled = ms[0x7fa4];
    s.localFastDiscovery = ms[0xc419];
    s.peerFound = peer != nullptr;
    if (peer != nullptr) {
        const UInt8 *fw = *reinterpret_cast<const UInt8 * const *>(
            reinterpret_cast<const UInt8 *>(peer) + 0x18);
        const UInt8 *ps = *reinterpret_cast<const UInt8 * const *>(
            reinterpret_cast<const UInt8 *>(peer) + 0x20);
        if (fw != nullptr) { s.fw240 = fw[0x240]; s.fw241 = fw[0x241]; }
        s.statePresent = ps != nullptr;
        if (ps != nullptr) {
            memcpy(&s.peerState, ps + 0x70, 4);
            memcpy(&s.options, ps + 0xcc, 4);
            memcpy(&s.options2, ps + 0xd0, 4);
            memcpy(&s.attempts, ps + 0x3c, 4);
            memcpy(&s.msecSinceAwdlOn, ps + 0x6a8, 4);
            s.peerSupport = (ps[0x1f9] & 8u) != 0;
            s.peerFastDiscovery = ps[0x6ac];
            s.bothSidesDiscovered = ps[0x6ad];
            s.pppDone = ps[0x6ae];
            s.waitingOnChain = ps[0x650];
            s.reliable = ps[0x4a];
        }
    }
    peerCacheObserveNative(airport, peerManager, &s);
    OSData *record = OSData::withBytes(&s, sizeof(s));
    if (record != nullptr) {
        airport->setProperty("AIRPLAYUmiSnapshotV1", record);
        record->release();
    }
}

static volatile UInt32 gBpfPreState=0;
static UInt32 gBpfPreCount=0xffffffff;
static UInt32 gBpfPrePacketState=0xffffffff;
static void
airplayRxFeedPublish(AirportItlwm *airport, bool force)
{
    if (airport == nullptr)
        return;
    struct timeval now;
    getmicrouptime(&now);
    if (!force && gRxFeedLastPublish.tv_sec != 0 &&
        (now.tv_sec - gRxFeedLastPublish.tv_sec) < 1)
        return;
    gRxFeedLastPublish = now;
#define RXFEED_PUB(name, val) airport->setProperty(name, (unsigned long long)(val), 32)
    RXFEED_PUB("AIRPLAYRxFeedEnabled", gRxFeedDisabled ? 0 : 1);
    RXFEED_PUB("AIRPLAYRxFeedCalls", gRxFeedCalls);
    RXFEED_PUB("AIRPLAYRxFeedDelivered", gRxFeedDelivered);
    RXFEED_PUB("AIRPLAYRxFeedDeliveredSeen", gRxFeedDelivered ? 1 : 0);
    RXFEED_PUB("AIRPLAYRxFeedNoInterface", gRxFeedNoInterface);
    RXFEED_PUB("AIRPLAYRxFeedNoPeerMgr", gRxFeedNoPeerMgr);
    RXFEED_PUB("AIRPLAYRxFeedNoPool", gRxFeedNoPool);
    RXFEED_PUB("AIRPLAYRxFeedNoBuffer", gRxFeedNoBuffer);
    RXFEED_PUB("AIRPLAYRxFeedCopyFail", gRxFeedCopyFail);
    RXFEED_PUB("AIRPLAYRxFeedBadLen", gRxFeedBadLen);
    RXFEED_PUB("AIRPLAYRxFeedPeerMgrPresent", gRxFeedPeerMgrPresent);
    RXFEED_PUB("AIRPLAYRxFeedPoolPresent", gRxFeedPoolPresent);
    RXFEED_PUB("AIRPLAYRxFeedIfRole", gRxFeedIfRole);
    RXFEED_PUB("AIRPLAYRxFeedLastLen", gRxFeedLastLen);
    RXFEED_PUB("AIRPLAYRxFeedLastChan", gRxFeedLastChan);
    RXFEED_PUB("AIRPLAYRxFeedLastSubtype", gRxFeedLastSubtype);
    RXFEED_PUB("AIRPLAYRxFeedLastRssiAbs", gRxFeedLastRssiAbs);
    RXFEED_PUB("AIRPLAYRxFeedChan6", gRxFeedChan6);
    RXFEED_PUB("AIRPLAYRxFeedChan5G", gRxFeedChan5G);
    if (__atomic_load_n(&gBpfPreState,__ATOMIC_ACQUIRE)==2) {
        RXFEED_PUB("AIRPLAYBpfPreCount",gBpfPreCount);
        RXFEED_PUB("AIRPLAYBpfPrePacketState",gBpfPrePacketState);
    }
#undef RXFEED_PUB
}

extern "C" void AirportItlwmAWDLSyncObserve(const uint8_t *sa, const uint8_t *body, size_t len); /* PSFSYNC */
#ifdef DEBUG
extern "C" void Mac1LinkV41AppleCacheObserve(const uint8_t *sa);
#endif

extern "C" void
AirportItlwmAWDLActionFrameRx(
    IOEthernetController *controller,
    const uint8_t *sa,
    const uint8_t *body,
    size_t bodyLen,
    int rssiDbm,
    unsigned int ieeeChan,
    bool is5GHz,
    uint32_t timestamp,
    uint32_t rate
)
{
    static int disabled = -1;
    if (disabled < 0) {
        int v = 0;
        disabled = PE_parse_boot_argn("-awdlrxoff", &v, sizeof(v)) ? 1 : 0;
    }

    AirportItlwm *airport = OSDynamicCast(AirportItlwm, controller);
    bool first = (gRxFeedCalls == 0);
    gRxFeedCalls++;

    do {
        if (disabled) {
            gRxFeedDisabled++;
            break;
        }
        if (sa == nullptr || body == nullptr || bodyLen < 8 || bodyLen > 2048) {
            gRxFeedBadLen++;
            break;
        }
        if (airport == nullptr || airport->fSonomaAWDLInterface == nullptr) {
            gRxFeedNoInterface++;
            break;
        }

        /* PSFSYNC-20261016: follow the cluster's AWDL timing from received PSF/MIF */
        AirportItlwmAWDLSyncObserve(sa, body, bodyLen);
        /* MIFRX-20261025 (observe-only): keep one received MIF (subtype 3) body for
         * offline type-12 Data Path State TLV decode (authoritative frame). */
        {
            static volatile UInt32 sMifRxSampled = 0;
            if (bodyLen > 6 && body[6] == 3 &&
                __sync_bool_compare_and_swap(&sMifRxSampled, 0, 1)) {
                OSData *mxs = OSData::withBytes(body,
                    (unsigned int)(bodyLen < 384 ? bodyLen : 384));
                if (mxs != nullptr) {
                    airport->setProperty("AIRPLAYMifRxSample", mxs);
                    mxs->release();
                }
                airport->setProperty("AIRPLAYMifRxSampleLen",
                                     (unsigned long long)bodyLen, 32);
            }
        }

        /* PSFTX-20261015 (read-only): keep one received PSF (subtype 0) for layout comparison */
        {
            static volatile UInt32 sPsfRxSampled = 0;
            if (bodyLen > 6 && body[6] == 0 &&
                __sync_bool_compare_and_swap(&sPsfRxSampled, 0, 1)) {
                OSData *rxs = OSData::withBytes(body, (unsigned int)(bodyLen < 384 ? bodyLen : 384));
                if (rxs != nullptr) {
                    airport->setProperty("AIRPLAYPsfRxSample", rxs);
                    rxs->release();
                }
                airport->setProperty("AIRPLAYPsfRxSampleLen", (unsigned long long)bodyLen, 32);
            }
        }
        AirportItlwmAWDLInterface *awdl = airport->fSonomaAWDLInterface;
        uint8_t *iv = airplayRxFeedIvars(awdl);
        void *peerMgr = iv ? *(void **)(iv + 0x30) : nullptr;
        gRxFeedIfRole = iv ? *(uint32_t *)(iv + 0x50) : 0;
        gRxFeedPeerMgrPresent = peerMgr ? 1 : 0;
        if (peerMgr == nullptr) {
            gRxFeedNoPeerMgr++;
            break;
        }
        /* MODEGATE-20261025 (observe-only): the AWDL "action-frame processing active"
         * flag that gates both actionFrameProcessInput's body (testb $2,16072 at its
         * entry) and setPeerRoutable's posting continuation (andl $2 on the same
         * (*(mgr+32))+16072). Read bit 0x2 plus the +50336 byte checked beside it.
         * Published ~1/sec; no behavior change. Boot-arg -awdlmodegateoff disables. */
        {
            static int sModeOff = -1;
            if (sModeOff < 0) {
                int mv = 0;
                sModeOff = PE_parse_boot_argn("-awdlmodegateoff", &mv, sizeof(mv)) ? 1 : 0;
            }
            static struct timeval sModeLast = {};
            struct timeval mnow; getmicrouptime(&mnow);
            if (!sModeOff &&
                (sModeLast.tv_sec == 0 || (mnow.tv_sec - sModeLast.tv_sec) >= 1)) {
                sModeLast = mnow;
                void *mgrSub = *reinterpret_cast<void **>(
                    reinterpret_cast<char *>(peerMgr) + 32);
                airport->setProperty("AIRPLAYGate16072SubPresent",
                                     (unsigned long long)(mgrSub ? 1 : 0), 32);
                if (mgrSub != nullptr) {
                    uint32_t f16072 = *reinterpret_cast<volatile uint32_t *>(
                        reinterpret_cast<char *>(mgrSub) + 16072);
                    uint8_t b50336 = *reinterpret_cast<volatile uint8_t *>(
                        reinterpret_cast<char *>(mgrSub) + 50336);
                    airport->setProperty("AIRPLAYGate16072",
                                         (unsigned long long)f16072, 32);
                    airport->setProperty("AIRPLAYGate16072Bit2",
                                         (unsigned long long)(f16072 & 2u), 32);
                    airport->setProperty("AIRPLAYGate50336",
                                         (unsigned long long)b50336, 32);
                    /* UMIPROBE-20261025 (observe-only): did the body set the peer
                     * category (0x03 at peer-state+204) and queue the peer to the UMI
                     * chain (membership +1616)? findCached(peerMgr, sa) -> peer. */
                    {
                        void **pmv2 = *reinterpret_cast<void ***>(peerMgr);
                        typedef void *(*AirplayFindCached2Fn)(void *, const uint8_t *);
                        AirplayFindCached2Fn fc2 =
                            reinterpret_cast<AirplayFindCached2Fn>(
                                pmv2[0x120 / sizeof(void *)]);
                        void *pr = fc2(peerMgr, sa);
#ifdef DEBUG
                        if (pr != nullptr) Mac1LinkV41AppleCacheObserve(sa);
#endif
                        airplayUmiPublishSnapshot(airport, peerMgr, mgrSub, pr, sa);
                        airport->setProperty("AIRPLAYUmiPeerFound",
                                             (unsigned long long)(pr ? 1 : 0), 32);
                        if (pr != nullptr) {
                            /* FWCACHE: observe Apple's firmware peer-cache
                             * indicators. No Apple state modifications. */
                            void *fwInfo = *reinterpret_cast<void **>(
                                reinterpret_cast<char *>(pr) + 0x18);

                            uint8_t fw240 = 0;
                            uint8_t fw241 = 0;

                            if (fwInfo != nullptr) {
                                fw240 = *reinterpret_cast<volatile uint8_t *>(
                                    reinterpret_cast<char *>(fwInfo) + 0x240);
                                fw241 = *reinterpret_cast<volatile uint8_t *>(
                                    reinterpret_cast<char *>(fwInfo) + 0x241);
                            }

                            airport->setProperty("AIRPLAYFWCacheInfoPresent",
                                (unsigned long long)(fwInfo != nullptr), 8);
                            airport->setProperty("AIRPLAYFWCache240",
                                (unsigned long long)fw240, 8);
                            airport->setProperty("AIRPLAYFWCache241",
                                (unsigned long long)fw241, 8);

                            void *ps = *reinterpret_cast<void **>(
                                reinterpret_cast<char *>(pr) + 32);
                            airport->setProperty("AIRPLAYUmiStatePresent",
                                                 (unsigned long long)(ps ? 1 : 0), 32);
                            if (ps != nullptr) {
                                /* MI110: read-only Apple AWDL peer processing observation. */
                                const uint8_t mi110 =
                                    *reinterpret_cast<volatile uint8_t *>(
                                        reinterpret_cast<uint8_t *>(ps) + 0x110);
                                airport->setProperty("AIRPLAYPeerMI110",
                                    (unsigned long long)mi110, 8);
                                /* P2PDSTATE70: read-only cached peer forwarding state. */
                                const uint32_t p2pdState70 =
                                    *reinterpret_cast<volatile uint32_t *>(
                                        reinterpret_cast<uint8_t *>(ps) + 0x70);
                                airport->setProperty("AIRPLAYPeerP2pdState70",
                                    (unsigned long long)p2pdState70, 32);
                                uint32_t cat = *reinterpret_cast<volatile uint32_t *>(
                                    reinterpret_cast<char *>(ps) + 204);
                                uint32_t mem = *reinterpret_cast<volatile uint32_t *>(
                                    reinterpret_cast<char *>(ps) + 1616);
                                uint8_t ppp = *reinterpret_cast<volatile uint8_t *>(
                                    reinterpret_cast<char *>(ps) + 1710);
                                airport->setProperty("AIRPLAYUmiCat204",
                                                     (unsigned long long)cat, 32);
                                airport->setProperty("AIRPLAYUmiCat204Hi",
                                                     (unsigned long long)((cat >> 24) & 0xffu), 32);
                                airport->setProperty("AIRPLAYUmiMember1616",
                                                     (unsigned long long)mem, 32);
                                airport->setProperty("AIRPLAYUmiPPP1710",
                                                     (unsigned long long)ppp, 32);
                                /* UMIGATE-20261025: fields gating the stamp block at
                                 * 0x20f8ad1/0x20f8ade -- +1708 (!=0) and +1704 (<=511);
                                 * +696 timestamp written on block entry (nonzero =>
                                 * block reached); +74 set at the stamp. */
                                uint8_t  g1708 = *reinterpret_cast<volatile uint8_t *>(
                                    reinterpret_cast<char *>(ps) + 1708);
                                uint32_t g1704 = *reinterpret_cast<volatile uint32_t *>(
                                    reinterpret_cast<char *>(ps) + 1704);
                                uint64_t t696 = *reinterpret_cast<volatile uint64_t *>(
                                    reinterpret_cast<char *>(ps) + 696);
                                uint8_t  b74 = *reinterpret_cast<volatile uint8_t *>(
                                    reinterpret_cast<char *>(ps) + 74);
                                airport->setProperty("AIRPLAYUmiFlag1708",
                                                     (unsigned long long)g1708, 32);
                                airport->setProperty("AIRPLAYUmiCount1704",
                                                     (unsigned long long)g1704, 32);
                                airport->setProperty("AIRPLAYUmiTs696NonZero",
                                                     (unsigned long long)(t696 ? 1 : 0), 32);
                                airport->setProperty("AIRPLAYUmiByte74",
                                                     (unsigned long long)b74, 32);
                                /* TLVBITS-20261025: sibling bits parseAwdlDataPathTLV
                                 * unpacks from the same flags word (bit6->+200,
                                 * bit9->+42, bit12->+201). All zero with +1708==0 =>
                                 * parse not running for this peer. */
                                uint8_t b200 = *reinterpret_cast<volatile uint8_t *>(
                                    reinterpret_cast<char *>(ps) + 200);
                                uint8_t b42  = *reinterpret_cast<volatile uint8_t *>(
                                    reinterpret_cast<char *>(ps) + 42);
                                uint8_t b201 = *reinterpret_cast<volatile uint8_t *>(
                                    reinterpret_cast<char *>(ps) + 201);
                                airport->setProperty("AIRPLAYUmiBit6_200",
                                                     (unsigned long long)b200, 32);
                                airport->setProperty("AIRPLAYUmiBit9_42",
                                                     (unsigned long long)b42, 32);
                                airport->setProperty("AIRPLAYUmiBit12_201",
                                                     (unsigned long long)b201, 32);
                            }
                        }
                    }
                }
            }
        }

        IO80211BufferPool *pool = awdl->getMgmtFramePool();
        gRxFeedPoolPresent = pool ? 1 : 0;
        if (pool == nullptr) {
            gRxFeedNoPool++;
            break;
        }

        /* pool->getBuffer(): virtual, vtable +0x118 (exactly as Apple's driver calls it). */
        typedef IO80211Buffer *(*AirplayGetBufferFn)(IO80211BufferPool *);
        AirplayGetBufferFn getBuffer =
            (AirplayGetBufferFn)((*(void ***)pool)[0x118 / sizeof(void *)]);
        IO80211Buffer *buf = getBuffer(pool);
        if (buf == nullptr) {
            gRxFeedNoBuffer++;
            break;
        }
        if (buf->writeBytes(0, body, bodyLen) != bodyLen) {
            gRxFeedCopyFail++;
            buf->returnBuffer();
            break;
        }
        buf->setLength(bodyLen);

        AirplayAFRxInfo info;
        bzero(&info, sizeof(info));
        memcpy(info.sa, sa, sizeof(info.sa));
        info.channel.version = 1;
        info.channel.channel = ieeeChan;
        info.channel.flags = (is5GHz ? APPLE80211_C_FLAG_5GHZ : APPLE80211_C_FLAG_2GHZ) |
                             APPLE80211_C_FLAG_20MHZ;
        info.rate = rate;
        info.rssi = rssiDbm != 0 ? rssiDbm : -1;
        info.timestamp = timestamp;

        /* BPF-PREHANDOFF probe: one observation only. */
        if (__sync_bool_compare_and_swap(&gBpfPreState,0,1)) {
            const UInt8 *ex = *reinterpret_cast<const UInt8 *const *>(reinterpret_cast<const UInt8 *>(awdl)+0x118);
            const UInt8 *pkt = ex ? *reinterpret_cast<const UInt8 *const *>(ex+0x60) : nullptr;
            if (pkt) {
                gBpfPreCount = *reinterpret_cast<const UInt32 *>(pkt+0x64);
                gBpfPrePacketState = *reinterpret_cast<const UInt16 *>(pkt+0x58);
            }
            __atomic_store_n(&gBpfPreState,2,__ATOMIC_RELEASE);
        }
        /* Ownership of buf passes to IO80211 here. */
        /* AFINPUT-20261025: deliver received AWDL action frames to Apple's
         * IO80211AWDLPeerManager::actionFrameInput so they drive peer discovery
         * (actionFrameProcessInput), not only the BPF tap. actionFrameInput is
         * non-virtual, so it is reached by applying the live KASLR slide (measured
         * from the peer-manager vtable pointer pmv) to its static address. It calls
         * sendToBpfTap itself, so pcap visibility is preserved. Static addresses are
         * from this machine's IO80211Family BootKC dump:
         *   __ZTV22IO80211AWDLPeerManager        = 0xffffff80022c9608  (vptr base +0x10)
         *   actionFrameInput(IO80211Buffer*,uint,void*,ulong) = 0xffffff80020f7a78
         * Guarded by actionFrameInput's prologue bytes; on mismatch (e.g. after an OS
         * update) or -awdlafinputoff, fall back to the original bpfTapInput tap. */
        static int sAfInputOff = -1;
        if (sAfInputOff < 0) {
            int v = 0;
            sAfInputOff = PE_parse_boot_argn("-awdlafinputoff", &v, sizeof(v)) ? 1 : 0;
        }
        static volatile UInt32 gRxFeedAFInputCalls = 0;
        static volatile UInt32 gRxFeedAFInputGuardFail = 0;
        static volatile UInt32 gRxFeedAFInputFallback = 0;
        /* AFGATE: observe Apple's actionFrameProcessInput mode gate. */
        static volatile UInt32 gAFGateOn = 0;
        static volatile UInt32 gAFGateOff = 0;
        static volatile UInt32 gAFGateNull = 0;
        static volatile UInt32 gAFGateLastFlags = 0;
        /* ELECTIONMATCH: received source versus Apple's selected election address. */
        static volatile UInt32 gAFElectionAddrMatch = 0;
        static volatile UInt32 gAFElectionAddrMismatch = 0;
        /* AFBYTE5: observe the sixth AWDL action-frame body byte. */
        static volatile UInt32 gAFByte5Zero = 0;
        static volatile UInt32 gAFByte5NonZero = 0;

        /* AFQUEUE: observe Apple's action-frame ring without modifying it. */
        static UInt32 gAFQSamples = 0;
        static UInt32 gAFQPrevWrite = 0;
        static UInt32 gAFQPrevRead = 0;
        static UInt32 gAFQWriteMoves = 0;
        static UInt32 gAFQReadMoves = 0;
        static UInt32 gAFQWriteIndex = 0;
        static UInt32 gAFQReadIndex = 0;
        static UInt32 gAFQDepth = 0;

        bool afDelivered = false;
        if (!sAfInputOff && peerMgr != nullptr) {
            void **pmv = *reinterpret_cast<void ***>(peerMgr);
            uintptr_t slide = reinterpret_cast<uintptr_t>(pmv) - 0xffffff80022c9618ULL;
            uintptr_t afiAddr = 0xffffff80020f7a78ULL + slide;
            static const uint8_t kAFIProlog[13] = {
                0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56,
                0x41, 0x55, 0x41, 0x54, 0x53 };
            if (memcmp(reinterpret_cast<const void *>(afiAddr),
                       kAFIProlog, sizeof(kAFIProlog)) == 0) {
                typedef void (*AirplayAFInputFn)(void *, IO80211Buffer *,
                                                 uint32_t, void *, size_t);
                AirplayAFInputFn afInput = reinterpret_cast<AirplayAFInputFn>(afiAddr);
                /* AFGATE: sample the Apple manager state immediately
                 * before actionFrameInput. Never modify Apple flags. */
                void *afGateState =
                    *reinterpret_cast<void * volatile *>(
                        reinterpret_cast<uint8_t *>(peerMgr) + 32);

                if (afGateState != nullptr) {
                    UInt32 flags =
                        *reinterpret_cast<volatile UInt32 *>(
                            reinterpret_cast<uint8_t *>(afGateState) + 16072);
                    gAFGateLastFlags = flags;
                    /* Observe the same six-byte comparison used by Apple's
                     * actionFrameProcessInput. Do not modify either address. */
                    const uint8_t *electionAddr =
                        reinterpret_cast<const uint8_t *>(afGateState) + 0x6a21;
                    if (memcmp(electionAddr, info.sa, 6) == 0)
                        gAFElectionAddrMatch++;
                    else
                        gAFElectionAddrMismatch++;
                    if (flags & 0x2)
                        gAFGateOn++;
                    else
                        gAFGateOff++;
                } else {
                    gAFGateNull++;
                }

                /* AFBYTE5: observe only; never modify packet contents. */
                if (bodyLen >= 6) {
                    if (body[5] == 0)
                        gAFByte5Zero++;
                    else
                        gAFByte5NonZero++;
                }
                /* AFQUEUE: sample before Apple's actionFrameInput. */
                if (afGateState != nullptr) {
                    const uint8_t *q =
                        reinterpret_cast<const uint8_t *>(afGateState);
                    UInt32 w = *reinterpret_cast<const volatile UInt32 *>(q + 0x41b0);
                    UInt32 r = *reinterpret_cast<const volatile UInt32 *>(q + 0x41b4);
                    UInt32 d = *reinterpret_cast<const volatile UInt32 *>(q + 0x41c0);

                    if (gAFQSamples != 0) {
                        if (w != gAFQPrevWrite) gAFQWriteMoves++;
                        if (r != gAFQPrevRead) gAFQReadMoves++;
                    }
                    gAFQPrevWrite = w;
                    gAFQPrevRead = r;
                    gAFQWriteIndex = w;
                    gAFQReadIndex = r;
                    gAFQDepth = d;
                    gAFQSamples++;
                }

                afInput(peerMgr, buf, 0xc, &info, sizeof(info));
                gRxFeedAFInputCalls++;
                afDelivered = true;
            } else {
                gRxFeedAFInputGuardFail++;
            }
        }
        if (!afDelivered) {
            awdl->bpfTapInput(buf, 0xc, &info, sizeof(info));
            gRxFeedAFInputFallback++;
        }
        {
            UInt32 total = gRxFeedAFInputCalls + gRxFeedAFInputFallback +
                           gRxFeedAFInputGuardFail;
            if (total <= 8 || (total % 64) == 0) {
                airport->setProperty("AIRPLAYRxFeedAFInputOn",
                                     (unsigned long long)(sAfInputOff ? 0 : 1), 32);
                airport->setProperty("AIRPLAYRxFeedAFInputCalls",
                                     (unsigned long long)gRxFeedAFInputCalls, 32);
                airport->setProperty("AIRPLAYRxFeedAFInputGuardFail",
                                     (unsigned long long)gRxFeedAFInputGuardFail, 32);
                airport->setProperty("AIRPLAYRxFeedAFGateOn",
                                      (unsigned long long)gAFGateOn, 32);
                airport->setProperty("AIRPLAYRxFeedAFGateOff",
                                      (unsigned long long)gAFGateOff, 32);
                airport->setProperty("AIRPLAYRxFeedAFGateNull",
                                      (unsigned long long)gAFGateNull, 32);
                airport->setProperty("AIRPLAYAFElectionAddrMatch",
                                      (unsigned long long)gAFElectionAddrMatch, 32);
                airport->setProperty("AIRPLAYAFElectionAddrMismatch",
                                      (unsigned long long)gAFElectionAddrMismatch, 32);
                airport->setProperty("AIRPLAYRxFeedAFGateLastFlags",
                                      (unsigned long long)gAFGateLastFlags, 32);
                airport->setProperty("AIRPLAYAFQSamples",
                    (unsigned long long)gAFQSamples, 32);
                airport->setProperty("AIRPLAYAFQWriteMoves",
                    (unsigned long long)gAFQWriteMoves, 32);
                airport->setProperty("AIRPLAYAFQReadMoves",
                    (unsigned long long)gAFQReadMoves, 32);
                airport->setProperty("AIRPLAYAFQWriteIndex",
                    (unsigned long long)gAFQWriteIndex, 32);
                airport->setProperty("AIRPLAYAFQReadIndex",
                    (unsigned long long)gAFQReadIndex, 32);
                airport->setProperty("AIRPLAYAFQDepth",
                    (unsigned long long)gAFQDepth, 32);
                airport->setProperty("AIRPLAYRxFeedAFByte5Zero",
                                      (unsigned long long)gAFByte5Zero, 32);
                airport->setProperty("AIRPLAYRxFeedAFByte5NonZero",
                                      (unsigned long long)gAFByte5NonZero, 32);
                airport->setProperty("AIRPLAYRxFeedAFInputFallback",
                                     (unsigned long long)gRxFeedAFInputFallback, 32);
            }
        }

        gRxFeedDelivered++;
        gRxFeedLastLen = (UInt32)bodyLen;
        gRxFeedLastChan = ieeeChan;
        gRxFeedLastSubtype = body[6];
        gRxFeedLastRssiAbs = (UInt32)(rssiDbm < 0 ? -rssiDbm : rssiDbm);
        if (is5GHz)
            gRxFeedChan5G++;
        else if (ieeeChan == 6)
            gRxFeedChan6++;

        /* GATEPROBE-20261017: observe-only read of the peer's isPeerRoutable inputs. */
        {
            static int gGateOff = -1;
            if (gGateOff < 0) {
                int gv = 0;
                gGateOff = PE_parse_boot_argn("-awdlgateoff", &gv, sizeof(gv)) ? 1 : 0;
            }
            static struct timeval sGateLast = {};
            struct timeval gnow; getmicrouptime(&gnow);
            if (!gGateOff && peerMgr != nullptr &&
                (sGateLast.tv_sec == 0 || (gnow.tv_sec - sGateLast.tv_sec) >= 1)) {
                sGateLast = gnow;
                void **pmv = *reinterpret_cast<void ***>(peerMgr);
                typedef void *(*AirplayFindCachedFn)(void *, const uint8_t *);
                AirplayFindCachedFn findCached =
                    reinterpret_cast<AirplayFindCachedFn>(pmv[0x120 / sizeof(void *)]);
                void *peer = findCached(peerMgr, sa);
                airport->setProperty("AIRPLAYGatePeerFound",
                    (unsigned long long)(peer != nullptr ? 1 : 0), 8);
                if (peer != nullptr) {
                    uint8_t *pp = reinterpret_cast<uint8_t *>(peer);
                    void *pA = *reinterpret_cast<void * volatile *>(pp + 0x18);
                    void *pB = *reinterpret_cast<void * volatile *>(pp + 0x20);
                    if (pB != nullptr) {
                        uint8_t *b = reinterpret_cast<uint8_t *>(pB);
                        airport->setProperty("AIRPLAYGateBand2e0",
                            (unsigned long long)(*reinterpret_cast<uint16_t volatile *>(b + 0x2e0)), 32);
                        airport->setProperty("AIRPLAYGateF70",
                            (unsigned long long)(*reinterpret_cast<uint32_t volatile *>(b + 0x70)), 32);
                        airport->setProperty("AIRPLAYGateF74",
                            (unsigned long long)(*reinterpret_cast<uint32_t volatile *>(b + 0x74)), 32);
                        /* FORCE-20261017 (Option B): satisfy isPeerRoutable (needs 0x70==2, 0x74>=2);
                         * dual-band/5GHz, !legacy, hasHTorVHTCaps, RSSI all already pass. DEFAULT OFF (-awdlforce).
                         * Persistent (re-applied each throttled pass) so a reset by IO80211 is overwritten. */
                        {
                            static int gForceOn = -1;
                            static UInt32 gForceApplied = 0;
                            if (gForceOn < 0) {
                                int fv = 0;
                                gForceOn = PE_parse_boot_argn("-awdlforce", &fv, sizeof(fv)) ? 1 : 0;
                            }
                            airport->setProperty("AIRPLAYForceOn", (unsigned long long)(gForceOn ? 1 : 0), 8);
                            if (gForceOn) {
                                *reinterpret_cast<uint32_t volatile *>(b + 0x70) = 2;
                                *reinterpret_cast<uint32_t volatile *>(b + 0x74) = 2;
                                gForceApplied++;
                                airport->setProperty("AIRPLAYForceApplied", (unsigned long long)gForceApplied, 32);
                                airport->setProperty("AIRPLAYForceF70After",
                                    (unsigned long long)(*reinterpret_cast<uint32_t volatile *>(b + 0x70)), 32);
                                airport->setProperty("AIRPLAYForceF74After",
                                    (unsigned long long)(*reinterpret_cast<uint32_t volatile *>(b + 0x74)), 32);
                            }
                        }
                    }
                    if (pA != nullptr) {
                        uint8_t *a = reinterpret_cast<uint8_t *>(pA);
                        airport->setProperty("AIRPLAYGateRssi48c",
                            (unsigned long long)(*reinterpret_cast<uint32_t volatile *>(a + 0x48c)), 32);
                        airport->setProperty("AIRPLAYGateRssi484",
                            (unsigned long long)(*reinterpret_cast<uint32_t volatile *>(a + 0x484)), 32);
                    }
                }
            }
        }
    } while (0);

    airplayRxFeedPublish(airport, first);
}

OSDefineMetaClassAndStructors(CTimeout, OSObject)

IO80211WorkQueue *_fWorkloop;
IOCommandGate *_fCommandGate;

void AirportItlwm::releaseAll()
{
    OSSafeReleaseNULL(driverLogPipe);
    OSSafeReleaseNULL(driverDataPathPipe);
    OSSafeReleaseNULL(driverSnapshotsPipe);
    OSSafeReleaseNULL(driverFaultReporter);
    if (fHalService) {
        fHalService->release();
        fHalService = NULL;
    }
    if (_fWorkloop) {
        if (_fCommandGate) {
//            _fCommandGate->disable();
            _fWorkloop->removeEventSource(_fCommandGate);
            _fCommandGate->release();
            _fCommandGate = NULL;
        }
        if (scanSource) {
            scanSource->cancelTimeout();
            scanSource->disable();
            _fWorkloop->removeEventSource(scanSource);
            scanSource->release();
            scanSource = NULL;
        }
        if (fWatchdogWorkLoop && watchdogTimer) {
            watchdogTimer->cancelTimeout();
            fWatchdogWorkLoop->removeEventSource(watchdogTimer);
            watchdogTimer->release();
            watchdogTimer = NULL;
            fWatchdogWorkLoop->release();
            fWatchdogWorkLoop = NULL;
        }
        _fWorkloop->release();
        _fWorkloop = NULL;
    }
    unregistPM();
}

void AirportItlwm::
eventHandler(struct ieee80211com *ic, int msgCode, void *data)
{
    AirportItlwm *that = OSDynamicCast(AirportItlwm, ic->ic_ac.ac_if.controller);
    IO80211SkywalkInterface *interface = that->fNetIf;
    if (!interface)
        return;
    switch (msgCode) {
        case IEEE80211_EVT_COUNTRY_CODE_UPDATE:
            interface->postMessage(APPLE80211_M_COUNTRY_CODE_CHANGED, NULL, 0, 0);
            break;
        case IEEE80211_EVT_STA_ASSOC_DONE:
            interface->postMessage(APPLE80211_M_ASSOC_DONE, NULL, 0, 0);
            break;
        case IEEE80211_EVT_STA_DEAUTH:
            interface->postMessage(APPLE80211_M_DEAUTH_RECEIVED, NULL, 0, 0);
            break;
        default:
            break;
    }
}

extern "C" bool airplayAwdlExperimentsEnabled(void);

/*
 * REGFIX: publish net80211 join-pipeline counters (ieee80211_js) to ioreg.
 */
static void regfixPublishJoinStats(IOService *svc, struct ieee80211com *ic)
{
#define REGFIX_JS(name, field) \
    svc->setProperty("AIRPLAYJOIN" name, (unsigned long long)ieee80211_js.field, 32)
    REGFIX_JS("EndScanCalls", endScanCalls);
    REGFIX_JS("EndScanBg", endScanBg);
    REGFIX_JS("EndScanEmptyTree", endScanEmptyTree);
    REGFIX_JS("EndScanNoCandidate", endScanNoCandidate);
    REGFIX_JS("EndScanJoinBss", endScanJoinBss);
    REGFIX_JS("EndScanJoinDesired", endScanJoinDesired);
    REGFIX_JS("DesiredSeen", desiredSeen);
    REGFIX_JS("DesiredSkippedFails", desiredSkippedFails);
    REGFIX_JS("DesiredMatchFail", desiredMatchFail);
    REGFIX_JS("DesiredLastFailBits", desiredLastFailBits);
    REGFIX_JS("StateToInit", stToInit);
    REGFIX_JS("StateToScan", stToScan);
    REGFIX_JS("StateRunToScan", stRunToScan);
    REGFIX_JS("StateToAuth", stToAuth);
    REGFIX_JS("StateToAssoc", stToAssoc);
    REGFIX_JS("StateToRun", stToRun);
    REGFIX_JS("TimeoutAuth", mgtTimeoutAuth);
    REGFIX_JS("TimeoutAssoc", mgtTimeoutAssoc);
    REGFIX_JS("LinkUpEvents", linkUp);
    REGFIX_JS("LinkDownEvents", linkDown);
#undef REGFIX_JS
#define AUTHPROBE_JS(name, field) \
    svc->setProperty("AIRPLAYAUTH" name, (unsigned long long)ieee80211_js.field, 32)
    AUTHPROBE_JS("Start", authStart);
    AUTHPROBE_JS("Err", authErr);
    AUTHPROBE_JS("LastErr", authLastErr);
    AUTHPROBE_JS("ChanMatch", authChanMatch);
    AUTHPROBE_JS("ChanMismatch", authChanMismatch);
    AUTHPROBE_JS("LastChan", authLastChan);
    AUTHPROBE_JS("ProtCmdErr", authProtCmdErr);
    AUTHPROBE_JS("ProtDurTU", authProtDurTU);
    AUTHPROBE_JS("ProtStart", authProtStart);
    AUTHPROBE_JS("ProtEnd", authProtEnd);
    AUTHPROBE_JS("ProtFail", authProtFail);
    AUTHPROBE_JS("ProtStartMs", authProtStartMs);
    AUTHPROBE_JS("ProtEndDuringJoin", authProtEndDuringJoin);
    AUTHPROBE_JS("TxBuilt", authTxBuilt);
    AUTHPROBE_JS("TxEnter", authTxEnter);
    AUTHPROBE_JS("TxToFw", authTxToFw);
    AUTHPROBE_JS("MgmtTxOk", authMgmtTxOk);
    AUTHPROBE_JS("MgmtTxFail", authMgmtTxFail);
    AUTHPROBE_JS("MgmtTxLastStatus", authMgmtTxLastStatus);
    AUTHPROBE_JS("RxFromTarget", authRxFromTarget);
    AUTHPROBE_JS("RxBeaconFromTarget", authRxBeaconFromTarget);
    AUTHPROBE_JS("RespRx", authRespRx);
    AUTHPROBE_JS("RespOk", authRespOk);
    AUTHPROBE_JS("RespFail", authRespFail);
    AUTHPROBE_JS("RespLastStatus", authRespLastStatus);
    AUTHPROBE_JS("RespWrongState", authRespWrongState);
    AUTHPROBE_JS("RespMs", authRespMs);
    AUTHPROBE_JS("Retry", authRetry);
    AUTHPROBE_JS("NewstateErr", authNewstateErr);
    AUTHPROBE_JS("NewstateErrState", authNewstateErrState);
    AUTHPROBE_JS("NewstateLastErr", authNewstateLastErr);
    /* BAND5PROBE */
    AUTHPROBE_JS("5GStart", a5Start);
    AUTHPROBE_JS("5GBandChange", a5BandChange);
    AUTHPROBE_JS("5GScanActive", a5ScanActive);
    AUTHPROBE_JS("5GPhyErr", a5PhyErr);
    AUTHPROBE_JS("5GPhyErrCount", a5PhyErrCount);
    AUTHPROBE_JS("5GTxToFw", a5TxToFw);
    AUTHPROBE_JS("5GLastRateNFlags", a5LastRateNFlags);
    AUTHPROBE_JS("5GMgmtTxOk", a5MgmtTxOk);
    AUTHPROBE_JS("5GMgmtTxFail", a5MgmtTxFail);
    AUTHPROBE_JS("5GMgmtTxLastStatus", a5MgmtTxLastStatus);
    AUTHPROBE_JS("5GRxFromTarget", a5RxFromTarget);
    AUTHPROBE_JS("5GRxBeacon", a5RxBeacon);
    AUTHPROBE_JS("5GRespRx", a5RespRx);
    AUTHPROBE_JS("5GRespOk", a5RespOk);
    AUTHPROBE_JS("5GTimeout", a5Timeout);
    /* AUTHDROP */
    AUTHPROBE_JS("DropRingEmpty", dropRingEmpty);
    AUTHPROBE_JS("DropTxBlocked", dropTxBlocked);
    AUTHPROBE_JS("DropSlotBusy", dropSlotBusy);
    AUTHPROBE_JS("DropSlotToken", dropSlotToken);
    AUTHPROBE_JS("DropAdmission", dropAdmission);
    AUTHPROBE_JS("DropNotRunning", dropNotRunning);
    AUTHPROBE_JS("DropMapFail", dropMapFail);
    AUTHPROBE_JS("DropLastQid", dropLastQid);
    AUTHPROBE_JS("DropLastIdx", dropLastIdx);
    AUTHPROBE_JS("DropLastQueued", dropLastQueued);
#undef AUTHPROBE_JS
    /* FLUSHRETIRE */
    svc->setProperty("AIRPLAYTXFlushCalls", (unsigned long long)ieee80211_js.flushCalls, 32);
    svc->setProperty("AIRPLAYTXFlushRetired", (unsigned long long)ieee80211_js.flushRetired, 32);
    /* FLUSHRECLAIM */
    svc->setProperty("AIRPLAYTXFlushQueuesReported", (unsigned long long)ieee80211_js.flushQueuesReported, 32);
    svc->setProperty("AIRPLAYTXFlushOldCheckWouldSkip", (unsigned long long)ieee80211_js.flushOldCheckWouldSkip, 32);
    svc->setProperty("AIRPLAYTXFlushRingNotLive", (unsigned long long)ieee80211_js.flushRingNotLive, 32);
#define AUTHPROBE_JS(name, field) \
    svc->setProperty("AIRPLAYAUTH" name, (unsigned long long)ieee80211_js.field, 32)
#undef AUTHPROBE_JS
    svc->setProperty("AIRPLAYJOINStateNow", (unsigned long long)(UInt32)ic->ic_state, 32);
    svc->setProperty("AIRPLAYJOINConnectedNow",
                     (unsigned long long)(ic->ic_state == IEEE80211_S_RUN ? 1 : 0), 32);
    svc->setProperty("AIRPLAYJOINKeysDoneNow",
                     (unsigned long long)((ic->ic_state == IEEE80211_S_RUN && ic->ic_bss != NULL &&
                                           (!(ic->ic_flags & IEEE80211_F_RSNON) || ic->ic_bss->ni_port_valid)) ? 1 : 0), 32);
    svc->setProperty("AIRPLAYAWDLExperimentsOn",
                     (unsigned long long)(airplayAwdlExperimentsEnabled() ? 1 : 0), 8);
    svc->setProperty("AIRPLAYJOINTargetSetNow",
                     (unsigned long long)(ic->ic_des_esslen != 0 ? 1 : 0), 32);
}

extern "C" bool airplayAwdlGetSyncActive(void); /* AWSTARTKEEP-20261024 */
void AirportItlwm::watchdogAction(IOTimerEventSource *timer)
{
    struct _ifnet *ifp = &fHalService->get80211Controller()->ic_ac.ac_if;
    (*ifp->if_watchdog)(ifp);

    updateLQMIfChanged();

    /*
     * Bounded AW-start cadence experiment.
     *
     * GP2 is a microsecond-domain firmware timer, so advance the
     * last confirmed firmware timestamp by one second for each
     * watchdog tick.
     */
    if (gAirplayAWStartCadenceBudget > 0 &&
        fSonomaAWDLInterface != nullptr) {

        UInt32 syntheticGP2 =
            gAirplayAWStartLastFirmwareTime + 1000000U;

        gAWProbeInCadence = 1;   /* AWPROBE: label this report as cadence */
        IOReturn cadenceResult =
            AirportItlwmReportAWDLStart(
                this,
                syntheticGP2,
                gAirplayAWStartLastChannel
            );
        gAWProbeInCadence = 0;

        gAirplayAWStartCadenceCount++;
        gAirplayAWStartCadenceBudget--;

        /* AWSTARTKEEP-20261024: real Intel STARTs stop when infra Wi-Fi blips, starving this
         * bounded budget so Apple logs "missing AW-start" and p2p-AirPlay control dies. Keep the
         * cadence alive while macOS still has AWDL sync enabled; stop cleanly when it disables it. */
        if (gAirplayAWStartCadenceBudget == 0 && airplayAwdlGetSyncActive()) {
            gAirplayAWStartCadenceBudget = 30;
        }

        setProperty(
            "AIRPLAYAWStartCadenceCount",
            (unsigned long long)
                gAirplayAWStartCadenceCount,
            32
        );

        setProperty(
            "AIRPLAYAWStartCadenceResult",
            (unsigned long long)(UInt32)
                cadenceResult,
            32
        );

        setProperty(
            "AIRPLAYAWStartCadenceBudget",
            (unsigned long long)
                gAirplayAWStartCadenceBudget,
            32
        );

        setProperty(
            "AIRPLAYAWStartCadenceGP2",
            (unsigned long long)
                syntheticGP2,
            32
        );
    }

    {
        static UInt32 sRegfixPublishedGen = 0xFFFFFFFF;
        static UInt32 sRegfixPublishedState = 0xFFFFFFFF;
        struct ieee80211com *jic = fHalService->get80211Controller();
        UInt32 g = ieee80211_js.gen;
        UInt32 st = (UInt32)jic->ic_state;
        if (g != sRegfixPublishedGen || st != sRegfixPublishedState) {
            sRegfixPublishedGen = g;
            sRegfixPublishedState = st;
            regfixPublishJoinStats(this, jic);
        }
    }

    watchdogTimer->setTimeoutMS(kWatchDogTimerPeriod);
}

// Compute and report Link Quality Metric. Replaces deprecated setLinkQualityMetric
// path on Sonoma 14.4+ Skywalk schema. SCDynamicStore key
// State:/Network/Interface/<if>/LinkQuality must be >= 11 for apsd /
// PCInterfaceUsabilityMonitor to consider the interface usable, otherwise the
// entire iServices stack (iMessage / FaceTime / AirDrop) refuses to use WiFi.
void AirportItlwm::updateLQMIfChanged()
{
    if (!fNetIf || !fHalService) {
        return;
    }
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (!ic || ic->ic_state != IEEE80211_S_RUN) {
        return;  // not associated; link-state mechanism signals unusable separately
    }
    // Snapshot ic_bss to a local — ieee80211 layer can clear it from another
    // workloop between our check and deref.
    struct ieee80211_node *ni = ic->ic_bss;
    if (!ni) {
        return;
    }
    // ni_rssi is normalized 0..(IWM_MAX_DBM - IWM_MIN_DBM)
    // i.e. 0 = -100 dBm, 67 = -33 dBm.
    int rssi_norm = ni->ni_rssi;
    unsigned long long lq;
    if (rssi_norm >= 30) {
        lq = 100;                // >= -70 dBm: excellent
    } else if (rssi_norm >= 15) {
        lq = 50;                 // >= -85 dBm: mediocre
    } else {
        lq = 25;                 // weak; still > iServices threshold (11)
    }
    if (lq != fLastReportedLQM) {
        fLastReportedLQM = lq;
        fNetIf->setLQM(lq);
    }
}

void AirportItlwm::fakeScanDone(OSObject *owner, IOTimerEventSource *sender)
{
    UInt32 msg = 0;
    AirportItlwm *that = (AirportItlwm *)owner;
    that->fNetIf->postMessage(APPLE80211_M_SCAN_DONE, &msg, 4, 0);
}

bool AirportItlwm::init(OSDictionary *properties)
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
    bool ret = super::init(properties);
    awdlSyncEnable = true;
    power_state = 0;
    fLastReportedLQM = 0;
    memset(geo_location_cc, 0, sizeof(geo_location_cc));
    return ret;
}

IOService* AirportItlwm::probe(IOService *provider, SInt32 *score)
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
    IOPCIEDeviceWrapper *wrapper = OSDynamicCast(IOPCIEDeviceWrapper, provider);
    if (!wrapper) {
        XYLog("%s Not a IOPCIEDeviceWrapper instance\n", __FUNCTION__);
        return NULL;
    }
    pciNub = wrapper->pciNub;
    fHalService = wrapper->fHalService;
    if (!pciNub || !fHalService) {
        XYLog("%s Not a valid IOPCIEDeviceWrapper instance\n", __FUNCTION__);
        return NULL;
    }
    return super::probe(provider, score);
}

#define LOWER32(x)  ((uint64_t)(x) & 0xffffffff)
#define HIGHER32(x) ((uint64_t)(x) >> 32)

bool AirportItlwm::
initCCLogs()
{
    CCPipeOptions driverLogOptions = { 0 };
    driverLogOptions.pipe_type = 0;
    driverLogOptions.log_data_type = 1;
    driverLogOptions.pipe_size = 0x200000;
    driverLogOptions.min_log_size_notify = 0xccccc;
    driverLogOptions.notify_threshold = 1000;
    strlcpy(driverLogOptions.file_name, "Itlwm_Logs", sizeof(driverLogOptions.file_name));
    snprintf(driverLogOptions.name, sizeof(driverLogOptions.name), "wlan%d", 0);
    strlcpy(driverLogOptions.directory_name, "WiFi", sizeof(driverLogOptions.directory_name));
    driverLogOptions.pad9 = 0x1000000;
    driverLogOptions.pad10 = 2;
    driverLogOptions.file_options = 0;
    driverLogOptions.log_policy = 0;
    driverLogPipe = CCPipe::withOwnerNameCapacity(this, "com.zxystd.AirportItlwm", "DriverLogs", &driverLogOptions);
    XYLog("%s driverLogPipeRet %d\n", __FUNCTION__, driverLogPipe != NULL);
    
    memset(&driverLogOptions, 0, sizeof(driverLogOptions));
    driverLogOptions.pipe_type = 0;
    driverLogOptions.log_data_type = 0;
    driverLogOptions.pipe_size = 0x200000;
    driverLogOptions.min_log_size_notify = 0xccccc;
    driverLogOptions.notify_threshold = 1000;
    strlcpy(driverLogOptions.file_name, "AppleBCMWLAN_Datapath", sizeof(driverLogOptions.file_name));
    strlcpy(driverLogOptions.directory_name, "WiFi", sizeof(driverLogOptions.directory_name));
    driverLogOptions.pad9 = HIGHER32(0x202800000);
    driverLogOptions.pad10 = LOWER32(0x202800000);
    driverLogOptions.file_options = 0;
    driverLogOptions.log_policy = 0;
    driverDataPathPipe = CCPipe::withOwnerNameCapacity(this, "com.zxystd.AirportItlwm", "DatapathEvents", &driverLogOptions);
    XYLog("%s driverDataPathPipeRet %d\n", __FUNCTION__, driverDataPathPipe != NULL);
    
    memset(&driverLogOptions, 0, sizeof(driverLogOptions));
    driverLogOptions.pipe_type = 0x200000001;
    driverLogOptions.log_data_type = 2;
    strlcpy(driverLogOptions.file_name, "StateSnapshots", sizeof(driverLogOptions.file_name));
    strlcpy(driverLogOptions.name, "0", sizeof(driverLogOptions.name));
    strlcpy(driverLogOptions.directory_name, "WiFi", sizeof(driverLogOptions.directory_name));
    driverLogOptions.pipe_size = 128;
    driverSnapshotsPipe = CCPipe::withOwnerNameCapacity(this, "com.zxystd.AirportItlwm", "StateSnapshots", &driverLogOptions);
    XYLog("%s driverSnapshotsPipeRet %d\n", __FUNCTION__, driverSnapshotsPipe != NULL);
    
    CCStreamOptions faultReportOptions = { 0 };
    faultReportOptions.stream_type = 1;
    faultReportOptions.console_level = 0xFFFFFFFFFFFFFFFF;
    driverFaultReporter = CCStream::withPipeAndName(driverSnapshotsPipe, "FaultReporter", &faultReportOptions);
    XYLog("%s driverFaultReporterRet %d\n", __FUNCTION__, driverFaultReporter != NULL);
    return driverLogPipe && driverDataPathPipe && driverSnapshotsPipe && driverFaultReporter;
}



bool
AirportItlwm::attachInterface(OSObject *object, IOService *provider)
{
    bool isAWDL =
        OSDynamicCast(AirportItlwmAWDLInterface, object) != nullptr;

    IOLog(
        "AIRPLAY V2 ATTACHIF: ENTER object=%p provider=%p awdl=%d\n",
        object,
        provider,
        isAWDL ? 1 : 0
    );

    if (isAWDL) {
        UInt8 value = 1;
        setProperty(
            "AIRPLAYAttachInterfaceAWDLEnter",
            OSData::withBytes(&value, sizeof(value))
        );
    }

    bool result =
        super::attachInterface(object, provider);

    /*
     * Cache only an AWDL protocol object that Apple actually accepted
     * through attachInterface().
     */
    if (isAWDL && result) {
        AirportItlwmAWDLInterface *awdl =
            OSDynamicCast(AirportItlwmAWDLInterface, object);

        if (awdl != nullptr) {
            gAirplayAWDLController = this;
            gAirplayAWDLInterface = awdl;

            setProperty(
                "AIRPLAYAWDLBridgeVIFCached",
                (unsigned long long)1,
                8
            );

            IOLog(
                "AIRPLAY AWDL BRIDGE: cached attached vif=%p controller=%p\n",
                awdl,
                this
            );
        }
    }

    IOLog(
        "AIRPLAY V2 ATTACHIF: RETURN=%d object=%p awdl=%d\n",
        result,
        object,
        isAWDL ? 1 : 0
    );

    if (isAWDL) {
        UInt8 value = result ? 1 : 0;
        setProperty(
            "AIRPLAYAttachInterfaceAWDLReturn",
            OSData::withBytes(&value, sizeof(value))
        );
    }

    return result;
}


IO80211VirtualInterface *AirportItlwm::
createVirtualInterface(ether_addr *ether, UInt role)
{
    UInt8 reached = 1;

    setProperty(
        "AIRPLAYSonomaFactoryReached",
        OSData::withBytes(&reached, sizeof(reached))
    );

    UInt8 roleValue = (UInt8)role;

    setProperty(
        "AIRPLAYSonomaFactoryRole",
        OSData::withBytes(&roleValue, sizeof(roleValue))
    );

    IOLog(
        "AIRPLAY CUSTOM ROLE6 FACTORY: role=%u ether=%p\n",
        (unsigned int)role,
        ether
    );

    IO80211VirtualInterface *vif = nullptr;

    if (role == APPLE80211_VIF_AWDL) {

        /*
         * Restore the Sonoma-compatible AWDL frontend.
         *
         * Do NOT use the legacy IO80211P2PInterface here and do NOT
         * use the plain IO80211VirtualInterface VIFBridge.  The latter
         * panicked synchronously in IO80211VirtualInterface::init().
         *
         * attachVirtualInterface() remains responsible for the normal
         * attach handoff, while probeAWDLInterfaceCreation() completes
         * start/enable/publication.
         */
        setProperty(
            "AIRPLAYCustomRole6FactoryRestored",
            (unsigned long long)1,
            8
        );

        memcpy(
            gAirplayAWDLAddress.octet,
            ether->octet,
            sizeof(gAirplayAWDLAddress.octet)
        );

        gAirplayAWDLAddressValid = true;

        AirportItlwmAWDLInterface *awdl =
            new AirportItlwmAWDLInterface;

        if (awdl != nullptr) {

            bool initialized = awdl->init(
                this,
                ether,
                role,
                "awdl"
            );

            setProperty(
                "AIRPLAYCustomRole6InitResult",
                (unsigned long long)(initialized ? 1 : 0),
                8
            );

            IOLog(
                "AIRPLAY CUSTOM ROLE6 FACTORY: init=%d object=%p\n",
                initialized,
                awdl
            );

            if (initialized) {
                vif = awdl;
            } else {
                awdl->release();
            }
        }

    } else {

        vif = super::createVirtualInterface(
            ether,
            role
        );
    }

    UInt8 returned = vif != nullptr ? 1 : 0;

    setProperty(
        "AIRPLAYSonomaFactoryReturnedNonNull",
        OSData::withBytes(&returned, sizeof(returned))
    );

    IOLog(
        "AIRPLAY CUSTOM ROLE6 FACTORY: returning=%p role=%u\n",
        vif,
        (unsigned int)role
    );

    return vif;
}


IOReturn AirportItlwm::
probeAWDLInterfaceCreation(apple80211_virt_if_create_data *data)
{
    if (data == nullptr)
        return kIOReturnBadArgument;

    if (data->role != APPLE80211_VIF_AWDL)
        return kIOReturnUnsupported;

    /*
     * Sonoma createProxInterface uses a locally administered
     * unicast address derived from the requested MAC.
     */
    struct ether_addr awdlAddress;

    memcpy(
        awdlAddress.octet,
        data->mac,
        sizeof(awdlAddress.octet)
    );

    awdlAddress.octet[0] =
        (awdlAddress.octet[0] & 0xFC) | 0x02;

    IOLog(
        "AIRPLAY V2 ATTACH: request role=%u\n",
        (unsigned int)data->role
    );

    IO80211VirtualInterface *vif = nullptr;

    bool attached = attachVirtualInterface(
        &vif,
        &awdlAddress,
        APPLE80211_VIF_AWDL,
        false
    );

    bool started = false;

    if (attached && vif != nullptr) {

        /*
         * Sonoma attachVirtualInterface() successfully attaches our
         * AirportItlwmAWDLInterface, but it does not necessarily pass
         * through AirportItlwm::attachInterface(), which was the old
         * location that populated the Intel -> AWDL event bridge cache.
         *
         * Cache the accepted custom role-6 object here so genuine Intel
         * P2P START notifications can reach reportDataPathEvents().
         */
        AirportItlwmAWDLInterface *awdlBridge =
            OSDynamicCast(AirportItlwmAWDLInterface, vif);

        if (awdlBridge != nullptr) {

            /*
             * KGP ownership model:
             * keep the successfully attached AWDL frontend on the
             * controller itself instead of relying on a side cache.
             */
            fSonomaAWDLInterface = awdlBridge;

            setProperty(
                "AIRPLAYKGPAWDLOwnershipInstalled",
                (unsigned long long)1,
                8
            );
            setProperty(
                "AIRPLAYAWDLBridgeCachedViaProbe",
                (unsigned long long)1,
                8
            );

            setProperty(
                "AIRPLAYAWDLBridgeControllerMatch",
                (unsigned long long)1,
                8
            );

            IOLog(
                "AIRPLAY AWDL BRIDGE: probe cached vif=%p controller=%p\n",
                awdlBridge,
                this
            );
        } else {
            setProperty(
                "AIRPLAYAWDLBridgeCachedViaProbe",
                (unsigned long long)0,
                8
            );
        }

        started = vif->start(this);

        /*
         * KGP-style completion of the virtual-interface lifecycle.
         *
         * Our Sonoma custom AWDL path reaches attach/start but Apple does not
         * subsequently invoke the controller's enableVirtualInterface()
         * callback. Complete that step explicitly once start() succeeds.
         */
        if (started) {
            SInt32 enableResult = enableVirtualInterface(vif);

            /*
             * KGP-style lifecycle completion for the Sonoma role-6 object.
             *
             * start() has completed and the controller has now explicitly
             * enabled the virtual interface.  Only at this point mark the
             * accepted AWDL object running.
             */
            if (enableResult == kIOReturnSuccess) {

                setProperty(
                    "AIRPLAYKGPFrontendPostEnableNonNull",
                    (unsigned long long)(vif != nullptr ? 1 : 0),
                    8
                );

                /*
                 * KGP explicitly publishes its AWDL P2P object.
                 *
                 * Our previous custom AirportItlwmAWDLInterface::start()
                 * did this internally.  A plain KGP P2P object does not
                 * use that custom start path, so publish it here.
                 */
                vif->registerService(kIOServiceSynchronous);

                setProperty(
                    "AIRPLAYKGPFrontendRegisterService",
                    (unsigned long long)1,
                    8
                );

                /*
                 * Do not cache this object in the old custom Skywalk
                 * AW-start bridge.  That event-42 branch has been ruled
                 * out and should remain inactive during this experiment.
                 */
                gAirplayAWDLController = nullptr;
                gAirplayAWDLInterface = nullptr;

                setProperty(
                    "AIRPLAYKGPFrontendSynthetic42Suppressed",
                    (unsigned long long)1,
                    8
                );

                IOLog(
                    "AIRPLAY KGP FRONTEND: enabled/published vif-valid=%d vif=%p\n",
                    vif != nullptr ? 1 : 0,
                    vif
                );
            }

            setProperty(
                "AIRPLAYKGPExplicitEnableResult",
                (unsigned long long)(uint32_t)enableResult,
                32
            );

            setProperty(
                "AIRPLAYKGPExplicitEnableAttempted",
                (unsigned long long)1,
                8
            );
        }
    }

    UInt8 attachedValue = attached ? 1 : 0;
    setProperty(
        "AIRPLAYSonomaAWDLAttached",
        OSData::withBytes(&attachedValue, sizeof(attachedValue))
    );

    UInt8 vifValue = vif ? 1 : 0;
    setProperty(
        "AIRPLAYSonomaAWDLVifNonNull",
        OSData::withBytes(&vifValue, sizeof(vifValue))
    );

    IOLog(
        "AIRPLAY V2 ATTACH: attach=%d vif=%p\n",
        attached,
        vif
    );

    if (!attached || !started || vif == nullptr)
        return kIOReturnError;

    const char *bsdName = vif->getBSDName();

    IOLog(
        "AIRPLAY V2 ATTACH: SUCCESS vif=%p bsd=%s role=%u\n",
        vif,
        bsdName ? bsdName : "(null)",
        (unsigned int)data->role
    );

    if (bsdName != nullptr && bsdName[0] != '\0') {
        strlcpy(
            (char *)data->bsd_name,
            bsdName,
            sizeof(data->bsd_name)
        );
    }

    return kIOReturnSuccess;
}


bool AirportItlwm::start(IOService *provider)
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
    struct IOSkywalkEthernetInterface::RegistrationInfo registInfo;
    int boot_value = 0;
    
    UInt8 builtIn = 0;
    setProperty("built-in", OSData::withBytes(&builtIn, sizeof(builtIn)));
    setProperty("DriverKitDriver", kOSBooleanFalse);
    if (!super::start(provider)) {
        return false;
    }
    pciNub->setBusMasterEnable(true);
    pciNub->setIOEnable(true);
    pciNub->setMemoryEnable(true);
    pciNub->configWrite8(0x41, 0);
    if (pciNub->requestPowerDomainState(kIOPMPowerOn,
                                        (IOPowerConnection *) getParentEntry(gIOPowerPlane), IOPMLowestState) != IOPMNoErr) {
        super::stop(provider);
        return false;
    }
    if (initPCIPowerManagment(pciNub) == false) {
        super::stop(pciNub);
        return false;
    }
    if (_fWorkloop == NULL) {
        XYLog("No _fWorkloop!!\n");
        super::stop(pciNub);
        releaseAll();
        return false;
    }
    _fCommandGate = IOCommandGate::commandGate(this, (IOCommandGate::Action)AirportItlwm::tsleepHandler);
    if (_fCommandGate == 0) {
        XYLog("No command gate!!\n");
        super::stop(pciNub);
        releaseAll();
        return false;
    }
    _fWorkloop->addEventSource(_fCommandGate);
    const IONetworkMedium *primaryMedium;
    if (!createMediumTables(&primaryMedium) ||
        !setCurrentMedium(primaryMedium) || !setSelectedMedium(primaryMedium)) {
        XYLog("setup medium fail\n");
        releaseAll();
        return false;
    }
    fHalService->initWithController(this, _fWorkloop, _fCommandGate);
    setProperty("AIRPLAYAddrSyncBuild", "AWDL-ADDRSYNC-V1");
    fHalService->get80211Controller()->ic_event_handler = eventHandler;
    
    if (PE_parse_boot_argn("-novht", &boot_value, sizeof(boot_value)))
        fHalService->get80211Controller()->ic_userflags |= IEEE80211_F_NOVHT;
    if (PE_parse_boot_argn("-noht40", &boot_value, sizeof(boot_value)))
        fHalService->get80211Controller()->ic_userflags |= IEEE80211_F_NOHT40;
    
    if (!fHalService->attach(pciNub)) {
        XYLog("attach fail\n");
        super::stop(pciNub);
        releaseAll();
        return false;
    }
    setProperty("AIRPLAYAddrSyncEnabled", awdlAddressSyncEnabled());
    setProperty("AIRPLAYPeerCacheBuild", "PEER-CACHE-PROBE-V1");
    setProperty("AIRPLAYPeerCacheCompletionImplemented", false);
    setProperty("AIRPLAYPeerCacheQueueWritesEnabled", false);
    setProperty("AIRPLAYPeerCacheTXEnabled", false);
    fWatchdogWorkLoop = IOWorkLoop::workLoop();
    if (fWatchdogWorkLoop == NULL) {
        XYLog("init watchdog workloop fail\n");
        fHalService->detach(pciNub);
        super::stop(pciNub);
        releaseAll();
        return false;
    }
    watchdogTimer = IOTimerEventSource::timerEventSource(this, OSMemberFunctionCast(IOTimerEventSource::Action, this, &AirportItlwm::watchdogAction));
    if (!watchdogTimer) {
        XYLog("init watchdog fail\n");
        fHalService->detach(pciNub);
        super::stop(pciNub);
        releaseAll();
        return false;
    }
    fWatchdogWorkLoop->addEventSource(watchdogTimer);
    scanSource = IOTimerEventSource::timerEventSource(this, &fakeScanDone);
    _fWorkloop->addEventSource(scanSource);
    scanSource->enable();

    fNetIf = new AirportItlwmSkywalkInterface;
    if (!fNetIf->init(this)) {
        XYLog("Skywalk interface init fail\n");
        super::stop(provider);
        releaseAll();
        return false;
    }
    fNetIf->setInterfaceRole(1);
    fNetIf->setInterfaceId(1);

    /*
     * Safe LowLatency role-2 / interface-id-9 probe.
     *
     * This candidate is NOT attached, started, registered,
     * or published to BSD.  It is released immediately.
     */
    {
        AirportItlwmSkywalkInterface *llwProbe =
            new AirportItlwmSkywalkInterface;

        setProperty(
            "AIRPLAYLLWProbeAllocated",
            (unsigned long long)(llwProbe != nullptr ? 1 : 0),
            8
        );

        if (llwProbe != nullptr) {
            bool llwInitialized =
                llwProbe->init(this);

            setProperty(
                "AIRPLAYLLWProbeInit",
                (unsigned long long)(llwInitialized ? 1 : 0),
                8
            );

            if (llwInitialized) {
                llwProbe->setInterfaceRole(2);
                llwProbe->setInterfaceId(9);

                int llwRole =
                    llwProbe->getInterfaceRole();

                const char *llwPrefix =
                    llwProbe->getBSDNamePrefix();

                bool llwPrefixMatches =
                    llwPrefix != nullptr &&
                    llwPrefix[0] == 'l' &&
                    llwPrefix[1] == 'l' &&
                    llwPrefix[2] == 'w' &&
                    llwPrefix[3] == '\0';

                setProperty(
                    "AIRPLAYLLWProbeRole",
                    (unsigned long long)(UInt32)llwRole,
                    32
                );

                setProperty(
                    "AIRPLAYLLWProbePrefixNonNull",
                    (unsigned long long)(llwPrefix != nullptr ? 1 : 0),
                    8
                );

                setProperty(
                    "AIRPLAYLLWProbePrefixIsLLW",
                    (unsigned long long)(llwPrefixMatches ? 1 : 0),
                    8
                );

                IOLog(
                    "AIRPLAY LLW PROBE: role=%d prefix=%s\n",
                    llwRole,
                    llwPrefix != nullptr ? llwPrefix : "<null>"
                );
            }

            llwProbe->release();
        }
    }
    
    if (!initCCLogs()) {
        XYLog("CCLog init fail\n");
        super::stop(provider);
        releaseAll();
        return false;
    }
    if (!fNetIf->attach(this)) {
        XYLog("attach to service fail\n");
        super::stop(provider);
        releaseAll();
        return false;
    }
    if (!attachInterface(fNetIf, this)) {
        XYLog("attach to interface fail\n");
        super::stop(provider);
        releaseAll();
        return false;
    }
    if (!IONetworkController::attachInterface((IONetworkInterface **)&bsdInterface, true)) {
        XYLog("attach to IONetworkController interface fail\n");
        super::stop(provider);
        releaseAll();
        return false;
    }
    memset(&registInfo, 0, sizeof(registInfo));
    if (!fNetIf->initRegistrationInfo(&registInfo, 1, sizeof(registInfo))) {
        XYLog("initRegistrationInfo fail\n");
        super::stop(provider);
        releaseAll();
        return false;
    }
    if (!fNetIf->initRegistrationInfo(&registInfo, 1, sizeof(registInfo))) {
        XYLog("initRegistrationInfo fail\n");
        super::stop(provider);
        releaseAll();
        return false;
    }
    fNetIf->mExpansionData->fRegistrationInfo = (struct IOSkywalkNetworkInterface::RegistrationInfo *)IOMalloc(sizeof(struct IOSkywalkNetworkInterface::RegistrationInfo));
    fNetIf->mExpansionData2->fRegistrationInfo = (struct IOSkywalkEthernetInterface::RegistrationInfo *)IOMalloc(sizeof(struct IOSkywalkEthernetInterface::RegistrationInfo));
    memcpy(fNetIf->mExpansionData->fRegistrationInfo, &registInfo, sizeof(registInfo));
    memcpy(fNetIf->mExpansionData2->fRegistrationInfo, &registInfo, sizeof(registInfo));
    if (fNetIf->getInterfaceRole() == 1)
        fNetIf->deferBSDAttach(true);
    fNetIf->start(this);
    
    setLinkStatus(kIONetworkLinkValid);
    if (TAILQ_EMPTY(&fHalService->get80211Controller()->ic_ess))
        fHalService->get80211Controller()->ic_flags |= IEEE80211_F_AUTO_JOIN;
    registerService();

    /*
     * Sonoma publishes the AWDL/AirLink virtual interface while idle.
     * Create it after the primary interface has been registered.
     *
     * Use the controller MAC as the base and apply the Sonoma
     * locally-administered unicast transformation:
     *
     *     first = (first & 0xFC) | 0x02
     *
     * Do not use the old last-byte XOR experiment.
     */
    struct ether_addr awdlAddress;

    memcpy(
        awdlAddress.octet,
        fHalService->get80211Controller()->ic_myaddr,
        sizeof(awdlAddress.octet)
    );

    awdlAddress.octet[0] =
        (awdlAddress.octet[0] & 0xFC) | 0x02;

    IO80211VirtualInterface *awdlVif = nullptr;

    IOLog(
        "AIRPLAY V2 BOOT ATTACH: requesting AWDL role=%u\n",
        (unsigned int)APPLE80211_VIF_AWDL
    );

    /*
     * V2 native-role6 hybrid:
     *
     * Sonoma has not naturally issued the AWDL create request in our tests.
     * Fill only that missing trigger here.
     *
     * probeAWDLInterfaceCreation() is part of this V2 target and calls
     * attachVirtualInterface().  createVirtualInterface(role 6) remains
     * delegated to native IO80211, so this does NOT instantiate our custom
     * AirportItlwmAWDLInterface.
     */
    apple80211_virt_if_create_data awdlCreateData = {};

    awdlCreateData.role = APPLE80211_VIF_AWDL;

    memcpy(
        awdlCreateData.mac,
        awdlAddress.octet,
        sizeof(awdlCreateData.mac)
    );

    strlcpy(
        (char *)awdlCreateData.bsd_name,
        "awdl0",
        sizeof(awdlCreateData.bsd_name)
    );

    setProperty(
        "AIRPLAYV2NativeBootProbeAttempted",
        (unsigned long long)1,
        8
    );

    IOReturn awdlProbeResult =
        probeAWDLInterfaceCreation(&awdlCreateData);

    setProperty(
        "AIRPLAYV2NativeBootProbeResult",
        (unsigned long long)(uint32_t)awdlProbeResult,
        32
    );

    IOLog(
        "AIRPLAY V2 NATIVE ROLE6: probe result=%d\n",
        awdlProbeResult
    );

    /*
     * probeAWDLInterfaceCreation() performs this experiment's
     * attach/start/enable sequence itself.
     *
     * Leave the older outer boot path disabled so that we do not
     * attach or start the same VIF twice.
     */
    bool awdlAttached = false;

    setProperty(
        "AIRPLAYKGPBootAttachSuppressed",
        (unsigned long long)1,
        8
    );

    bool awdlStarted = false;

    if (awdlAttached && awdlVif != nullptr) {
        bool awdlSkywalkAttached =
            attachInterface(awdlVif, this);

        UInt8 awdlSkywalkAttachedValue =
            awdlSkywalkAttached ? 1 : 0;

        setProperty(
            "AIRPLAYBootSkywalkAttachResult",
            OSData::withBytes(
                &awdlSkywalkAttachedValue,
                sizeof(awdlSkywalkAttachedValue)
            )
        );

        if (awdlSkywalkAttached) {
            awdlStarted = awdlVif->start(this);

            /*
             * KGP-style completion of the real Sonoma boot AWDL VIF path.
             *
             * The custom boot attach/start path bypasses the controller's
             * normal enableVirtualInterface() lifecycle. Complete it here
             * after the AWDL VIF successfully starts.
             */
            if (awdlStarted) {
                setProperty(
                    "AIRPLAYKGPBootExplicitEnableAttempted",
                    (unsigned long long)1,
                    8
                );

                SInt32 enableResult =
                    enableVirtualInterface(awdlVif);

                setProperty(
                    "AIRPLAYKGPBootExplicitEnableResult",
                    (unsigned long long)(uint32_t)enableResult,
                    32
                );
            }
        }
    }

    if (awdlAttached && awdlVif != nullptr) {
        ifnet_t awdlBSDIf = awdlVif->getBSDInterface();
        const char *awdlBSDName = awdlVif->getBSDName();
        const char *awdlBSDPrefix = awdlVif->getBSDNamePrefix();
        UInt awdlBSDUnit = awdlVif->getBSDUnitNumber();

        UInt8 bsdIfNonNull = awdlBSDIf != nullptr ? 1 : 0;
        UInt8 bsdNameNonNull =
            (awdlBSDName != nullptr && awdlBSDName[0] != '\0') ? 1 : 0;
        UInt8 bsdPrefixNonNull =
            (awdlBSDPrefix != nullptr && awdlBSDPrefix[0] != '\0') ? 1 : 0;

        setProperty(
            "AIRPLAYBootBSDIfNonNull",
            OSData::withBytes(&bsdIfNonNull, sizeof(bsdIfNonNull))
        );

        setProperty(
            "AIRPLAYBootBSDNameNonNull",
            OSData::withBytes(&bsdNameNonNull, sizeof(bsdNameNonNull))
        );

        setProperty(
            "AIRPLAYBootBSDPrefixNonNull",
            OSData::withBytes(&bsdPrefixNonNull, sizeof(bsdPrefixNonNull))
        );

        setProperty(
            "AIRPLAYBootBSDUnit",
            OSData::withBytes(&awdlBSDUnit, sizeof(awdlBSDUnit))
        );

        IOLog(
            "AIRPLAY V2 BOOT BSD STATE: ifp=%p name=%s prefix=%s unit=%u\n",
            awdlBSDIf,
            awdlBSDName ? awdlBSDName : "(null)",
            awdlBSDPrefix ? awdlBSDPrefix : "(null)",
            (unsigned int)awdlBSDUnit
        );
    }

    UInt8 awdlStartedValue = awdlStarted ? 1 : 0;
    setProperty(
        "AIRPLAYSonomaBootAWDLStarted",
        OSData::withBytes(
            &awdlStartedValue,
            sizeof(awdlStartedValue)
        )
    );

    UInt8 awdlAttachedValue = awdlAttached ? 1 : 0;
    setProperty(
        "AIRPLAYSonomaBootAWDLAttached",
        OSData::withBytes(
            &awdlAttachedValue,
            sizeof(awdlAttachedValue)
        )
    );

    UInt8 awdlVifValue = awdlVif ? 1 : 0;
    setProperty(
        "AIRPLAYSonomaBootAWDLVifNonNull",
        OSData::withBytes(
            &awdlVifValue,
            sizeof(awdlVifValue)
        )
    );

    IOLog(
        "AIRPLAY V2 BOOT ATTACH: attach=%d vif=%p\n",
        awdlAttached,
        awdlVif
    );

    return true;
}

void AirportItlwm::stop(IOService *provider)
{
    __atomic_store_n(&fAddrSyncStopping, 1U, __ATOMIC_RELEASE);
    /* Worker uses attemptAction, so draining here cannot wait on a worker
     * blocked on this gate during taskq teardown. No new timer/lifetime. */
    if (getCommandGate()) getCommandGate()->runAction(awdlAddressSyncDrainAction);
    XYLog("%s\n", __PRETTY_FUNCTION__);XYLog("%s\n", __PRETTY_FUNCTION__);
    struct _ifnet *ifp = &fHalService->get80211Controller()->ic_ac.ac_if;
    super::stop(provider);
    disableAdapter(bsdInterface);
    setLinkStatus(kIONetworkLinkValid);
    fHalService->detach(pciNub);
    ether_ifdetach(ifp);
    detachInterface(fNetIf, true);
    OSSafeReleaseNULL(fNetIf);
    releaseAll();
}

void AirportItlwm::free()
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
    if (fHalService != NULL) {
        fHalService->release();
        fHalService = NULL;
    }
    if (syncFrameTemplate != NULL && syncFrameTemplateLength > 0) {
        IOFree(syncFrameTemplate, syncFrameTemplateLength);
        syncFrameTemplateLength = 0;
        syncFrameTemplate = NULL;
    }
    if (roamProfile != NULL) {
        IOFree(roamProfile, sizeof(struct apple80211_roam_profile_band_data));
        roamProfile = NULL;
    }
    if (btcProfile != NULL) {
        IOFree(btcProfile, sizeof(struct apple80211_btc_profiles_data));
        btcProfile = NULL;
    }
    super::free();
}

bool AirportItlwm::createWorkQueue()
{
    XYLog("%s %d\n", __FUNCTION__, _fWorkloop != 0);
    return _fWorkloop != 0;
}

IO80211WorkQueue *AirportItlwm::getWorkQueue()
{
    return _fWorkloop;
}

void *AirportItlwm::getFaultReporterFromDriver()
{
    return driverFaultReporter;
}

IOReturn AirportItlwm::enable(IO80211SkywalkInterface *netif)
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
    super::enable(netif);
    _fCommandGate->enable();
    if (power_state)
        enableAdapter(bsdInterface);
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::disable(IO80211SkywalkInterface *netif)
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
    super::disable(netif);
    setLinkStatus(kIONetworkLinkValid);
    return kIOReturnSuccess;
}

bool AirportItlwm::configureInterface(IONetworkInterface *netif)
{
    IONetworkData *nd;
    struct _ifnet *ifp = &fHalService->get80211Controller()->ic_ac.ac_if;
    
    if (super::configureInterface(netif) == false) {
        XYLog("super failed\n");
        return false;
    }
    
    nd = netif->getParameter(kIONetworkStatsKey);
    if (!nd || !(fpNetStats = (IONetworkStats *)nd->getBuffer())) {
        XYLog("network statistics buffer unavailable?\n");
        return false;
    }
    ifp->netStat = fpNetStats;
    ether_ifattach(ifp, OSDynamicCast(IOEthernetInterface, netif));
    fpNetStats->collisions = 0;
#ifdef __PRIVATE_SPI__
    netif->configureOutputPullModel(fHalService->getDriverInfo()->getTxQueueSize(), 0, 0, IOEthernetInterface::kOutputPacketSchedulingModelNormal, 0);
#endif
    
    return true;
}

IONetworkInterface *AirportItlwm::createInterface()
{
    AirportItlwmEthernetInterface *netif = new AirportItlwmEthernetInterface;
    if (!netif)
        return NULL;
    if (!netif->initWithSkywalkInterfaceAndProvider(this, fNetIf)) {
        netif->release();
        return NULL;
    }
    return netif;
}

bool AirportItlwm::createMediumTables(const IONetworkMedium **primary)
{
    IONetworkMedium    *medium;

    OSDictionary *mediumDict = OSDictionary::withCapacity(2);
    if (mediumDict == NULL) {
        XYLog("Cannot allocate OSDictionary\n");
        return false;
    }
    
    medium = IONetworkMedium::medium(kIOMediumIEEE80211, 54000000);
    IONetworkMedium::addMedium(mediumDict, medium);
    medium->release();
    if (primary) {
        *primary = medium;
    }
    medium = IONetworkMedium::medium(kIOMediumIEEE80211None, 0);
    IONetworkMedium::addMedium(mediumDict, medium);
    medium->release();
    
    bool result = publishMediumDictionary(mediumDict);
    if (!result) {
        XYLog("Cannot publish medium dictionary!\n");
    }

    mediumDict->release();
    return result;
}

IOReturn AirportItlwm::selectMedium(const IONetworkMedium *medium) {
    setSelectedMedium(medium);
    return kIOReturnSuccess;
}

bool AirportItlwm::
setLinkStatus(UInt32 status, const IONetworkMedium * activeMedium, UInt64 speed, OSData * data)
{
    struct _ifnet *ifq = &fHalService->get80211Controller()->ic_ac.ac_if;
    if (status == currentStatus) {
        return true;
    }
    bool ret = super::setLinkStatus(status, activeMedium, speed, data);
    currentStatus = status;
    /* SEQFIX: sequencing state shared with AirportItlwmSkywalkInterface.cpp */
    {
        extern volatile UInt32 gSeqVoluntaryDown;
        extern volatile UInt32 gSeqJoinInFlight;
        extern volatile UInt32 gSeqStaleLinkDown;
        extern volatile uint64_t gSeqAssocStampMs;
        static uint64_t sSeqLinkUpStampMs = 0;
        static UInt32 sSeqUp = 0, sSeqDown = 0, sSeqShort = 0;
        static uint64_t sSeqAssocToUpMax = 0;
        uint64_t seqNow = airport_up_time();
        if (status & kIONetworkLinkActive) {
            sSeqLinkUpStampMs = seqNow;
            setProperty("AIRPLAYSEQLinkUpCount", (unsigned long long)++sSeqUp, 32);
            if (gSeqAssocStampMs != 0 && seqNow >= gSeqAssocStampMs) {
                uint64_t d = seqNow - gSeqAssocStampMs;
                if (d > sSeqAssocToUpMax) sSeqAssocToUpMax = d;
                setProperty("AIRPLAYSEQAssocToLinkUpMs", (unsigned long long)d, 32);
                setProperty("AIRPLAYSEQAssocToLinkUpMaxMs", (unsigned long long)sSeqAssocToUpMax, 32);
                gSeqAssocStampMs = 0;
            }
        } else {
            setProperty("AIRPLAYSEQLinkDownCount", (unsigned long long)++sSeqDown, 32);
            if (sSeqLinkUpStampMs != 0 && seqNow >= sSeqLinkUpStampMs) {
                uint64_t life = seqNow - sSeqLinkUpStampMs;
                setProperty("AIRPLAYSEQLastLinkLifetimeMs", (unsigned long long)life, 32);
                if (life < 5000)
                    setProperty("AIRPLAYSEQShortLivedLinks", (unsigned long long)++sSeqShort, 32);
            }
            sSeqLinkUpStampMs = 0;
        }
        if (status & kIONetworkLinkActive) {
            /* new link is up: a later drop is involuntary unless macOS asks */
            __sync_lock_test_and_set(&gSeqVoluntaryDown, (UInt32)0);
            __sync_lock_test_and_set(&gSeqJoinInFlight, (UInt32)0);
            setProperty("AIRPLAYSEQJoinInFlight", (unsigned long long)0, 32);
        } else if (gSeqJoinInFlight) {
            /* old bug signature: a link-down arriving after a new join started */
            UInt32 s = __sync_add_and_fetch(&gSeqStaleLinkDown, (UInt32)1);
            setProperty("AIRPLAYSEQStaleLinkDownAfterAssoc", (unsigned long long)s, 32);
        }
    }
    if (fNetIf) {
        if (status & kIONetworkLinkActive) {
#ifdef __PRIVATE_SPI__
            bsdInterface->startOutputThread();
#endif
            getCommandGate()->runAction(setLinkStateGated, (void *)kIO80211NetworkLinkUp, (void *)0);
        } else if (!(status & kIONetworkLinkNoNetworkChange)) {
#ifdef __PRIVATE_SPI__
            bsdInterface->stopOutputThread();
            bsdInterface->flushOutputQueue();
#endif
            ifq_flush(&ifq->if_snd);
            mq_purge(&fHalService->get80211Controller()->ic_mgtq);
            getCommandGate()->runAction(setLinkStateGated, (void *)kIO80211NetworkLinkDown, (void *)fHalService->get80211Controller()->ic_deauth_reason);
        }
    }
    return ret;
}

IOReturn AirportItlwm::
setLinkStateGated(OSObject *target, void *arg0, void *arg1, void *arg2, void *arg3)
{
    AirportItlwm *that = OSDynamicCast(AirportItlwm, target);
    /*
     * NODEBOUNCE-20261010: setLinkState's 3rd parameter (debounce) defaults to
     * true (header: bool debounceTimeout = 30). Calling it with 2 args made
     * EVERY link-down a debounced one, including the one we report for a
     * DISASSOCIATE macOS asked for. airportd: "linkDown (1), debounce (1)" ->
     * APPLE80211_M_LINK_DOWN_DEBOUNCE_FAILED (191) -> "Unexpected link down.
     * Triggering auto-join" -> auto-join pulls back to the previous network
     * (the 2.4 <-> 5 switch bounce). Host-requested downs: no debounce.
     * Real drops (beacon loss, AP deauth) keep the debounce.
     */
    extern volatile UInt32 gSeqVoluntaryDown;
    static UInt32 sNoDebounceDowns = 0, sDebouncedDowns = 0;
    IO80211LinkState nbState = (IO80211LinkState)(uint64_t)arg0;
    bool nbDebounce = true;
    if (nbState == kIO80211NetworkLinkDown) {
        if (gSeqVoluntaryDown) {
            nbDebounce = false;
            that->setProperty("AIRPLAYSEQLinkDownNoDebounce", (unsigned long long)++sNoDebounceDowns, 32);
        } else {
            that->setProperty("AIRPLAYSEQLinkDownDebounced", (unsigned long long)++sDebouncedDowns, 32);
        }
        that->setProperty("AIRPLAYSEQLastLinkDownDebounce", (unsigned long long)(nbDebounce ? 1 : 0), 32);
    }
    IOReturn ret = that->fNetIf->setLinkState(nbState, (unsigned int)(uint64_t)arg1, nbDebounce, 0);
    that->fNetIf->setRunningState((IO80211LinkState)(uint64_t)arg0 == kIO80211NetworkLinkUp);

    /*
     * KGP propagates the primary controller link state to AWDL too.
     * Our AWDL object is cached after successful attachInterface().
     */
    if (gAirplayAWDLInterface != nullptr &&
        airplayAwdlExperimentsEnabled()) {

        if ((IO80211LinkState)(uint64_t)arg0 ==
            kIO80211NetworkLinkUp) {
            gAirplayAWDLInterface->setEnabledBySystem(true);
        }

        gAirplayAWDLInterface->setLinkState(
            (IO80211LinkState)(uint64_t)arg0,
            (unsigned int)(uint64_t)arg1
        );

        gAirplayAWDLInterface->postMessage(
            APPLE80211_M_LINK_CHANGED,
            nullptr,
            0,
            false
        );

        that->setProperty(
            "AIRPLAYKGPAWDLLinkPropagated",
            (unsigned long long)1,
            8
        );
    }
    that->fNetIf->postMessage(APPLE80211_M_LINK_CHANGED, NULL, 0, false);
    that->fNetIf->postMessage(APPLE80211_M_BSSID_CHANGED, NULL, 0, false);
    that->fNetIf->postMessage(APPLE80211_M_SSID_CHANGED, NULL, 0, false);
    if ((IO80211LinkState)(uint64_t)arg0 == kIO80211NetworkLinkUp) {
        that->fNetIf->reportLinkStatus(3, 0x80);
        that->updateLQMIfChanged();
    } else {
        that->fNetIf->reportLinkStatus(1, 0);
        that->fLastReportedLQM = 0;
    }
    that->bsdInterface->setLinkState((IO80211LinkState)(uint64_t)arg0);
    return ret;
}

#ifdef __PRIVATE_SPI__
IOReturn AirportItlwm::outputStart(IONetworkInterface *interface, IOOptionBits options)
{
    struct _ifnet *ifp = &fHalService->get80211Controller()->ic_ac.ac_if;
    mbuf_t m = NULL;
    if (ifq_is_oactive(&ifp->if_snd))
        return kIOReturnNoResources;
    while (kIOReturnSuccess == interface->dequeueOutputPackets(1, &m)) {
        if (outputPacket(m, NULL)!= kIOReturnOutputSuccess ||
            ifq_is_oactive(&ifp->if_snd))
            return kIOReturnNoResources;
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::networkInterfaceNotification(
                    IONetworkInterface * interface,
                    uint32_t              type,
                    void *                  argument )
{
    XYLog("%s\n", __FUNCTION__);
    return kIOReturnSuccess;
}
#endif

extern const char* hexdump(uint8_t *buf, size_t len);

UInt32 AirportItlwm::outputPacket(mbuf_t m, void *param)
{
//    XYLog("%s\n", __FUNCTION__);
    IOReturn ret = kIOReturnOutputSuccess;
    struct _ifnet *ifp = &fHalService->get80211Controller()->ic_ac.ac_if;
    
    if (fHalService->get80211Controller()->ic_state != IEEE80211_S_RUN || ifp->if_snd.queue == NULL) {
        if (m && mbuf_type(m) != MBUF_TYPE_FREE)
            freePacket(m);
        return kIOReturnOutputDropped;
    }
    if (m == NULL) {
        XYLog("%s m==NULL!!\n", __FUNCTION__);
        ifp->netStat->outputErrors++;
        ret = kIOReturnOutputDropped;
    }
    if (!(mbuf_flags(m) & MBUF_PKTHDR) ){
        XYLog("%s pkthdr is NULL!!\n", __FUNCTION__);
        ifp->netStat->outputErrors++;
        freePacket(m);
        ret = kIOReturnOutputDropped;
    }
    if (mbuf_type(m) == MBUF_TYPE_FREE) {
        XYLog("%s mbuf is FREE!!\n", __FUNCTION__);
        ifp->netStat->outputErrors++;
        ret = kIOReturnOutputDropped;
    }
    size_t len = mbuf_len(m);
    ether_header_t *eh = (ether_header_t *)mbuf_data(m);
    if (len >= sizeof(ether_header_t) && eh->ether_type == htons(ETHERTYPE_PAE)) { // EAPOL packet
        const char* dump = hexdump((uint8_t*)mbuf_data(m), len);
        XYLog("output EAPOL packet, len: %zu, data: %s\n", len, dump ? dump : "Failed to allocate memory");
        if (dump)
            IOFree((void*)dump, 3 * len + 1);
    }
    if (!ifp->if_snd.queue->lockEnqueue(m)) {
        freePacket(m);
        ret = kIOReturnOutputDropped;
    }
    (*ifp->if_start)(ifp);
    return ret;
}

const OSString * AirportItlwm::newVendorString() const
{
    return OSString::withCString("Apple");
}

const OSString * AirportItlwm::newModelString() const
{
    return OSString::withCString(fHalService->getDriverInfo()->getFirmwareName());
}

IOReturn AirportItlwm::getHardwareAddress(IOEthernetAddress *addrP)
{
    if (IEEE80211_ADDR_EQ(etheranyaddr, fHalService->get80211Controller()->ic_myaddr))
        return kIOReturnError;
    else {
        IEEE80211_ADDR_COPY(addrP, fHalService->get80211Controller()->ic_myaddr);
        return kIOReturnSuccess;
    }
}


#include "AWDLAddressSyncV1.inc"
#include "PeerCacheControllerV1.inc"

/* AIRPLAYVMACPROBE plus ADDRSYNC-V1's AWDL-only handled callback. */
SInt32 AirportItlwm::setVirtualHardwareAddress(
    IO80211VirtualInterface *interface,
    ether_addr *address
)
{
    static volatile UInt32 calls = 0;

    const UInt32 count = __atomic_add_fetch(
        &calls, (UInt32)1, __ATOMIC_RELAXED
    );

    setProperty("AIRPLAYVMACProbeCalls",
                (unsigned long long)count, 32);

    setProperty("AIRPLAYVMACProbeInterfacePresent",
                (unsigned long long)(interface != nullptr), 8);

    setProperty("AIRPLAYVMACProbeAddressPresent",
                (unsigned long long)(address != nullptr), 8);

    SInt32 result;
    if (awdlAddressSyncEnabled() && interface == fSonomaAWDLInterface) {
        if (!awdlAddressValid(address) || !getCommandGate() ||
            __atomic_load_n(&fAddrSyncStopping, __ATOMIC_ACQUIRE)) return EINVAL;
        /* The controller callback reports EINPROGRESS while deferred, never
         * a fabricated hardware success. BSD setter success is separate.
         * Native setHardwareAddress is void and forwards this callback; the
         * existing BSD bridge applies its own address and result separately. */
        AWDLAddrSyncRequest request{*address, EINPROGRESS};
        result = getCommandGate()->runAction(awdlAddressSyncRequestAction, &request)
            == kIOReturnSuccess ? request.result : EBUSY;
        setProperty("AIRPLAYVMACProbeHandled", true);
    } else {
        result = IO80211Controller::setVirtualHardwareAddress(interface, address);
        setProperty("AIRPLAYVMACProbeBaseResult", (unsigned long long)(UInt32)result, 32);
    }

    setProperty("AIRPLAYVMACProbeReturnedResult",
                (unsigned long long)(UInt32)result, 32);

    return result;
}

IOReturn AirportItlwm::setHardwareAddress(const void *addrP, UInt32 addrBytes)
{
    if (!fNetIf || !addrP)
        return kIOReturnError;
    if_setlladdr(&fHalService->get80211Controller()->ic_ac.ac_if, (const UInt8 *)addrP);
    if (fHalService->get80211Controller()->ic_state > IEEE80211_S_INIT) {
        fHalService->disable(bsdInterface);
        fHalService->enable(bsdInterface);
    }
    return kIOReturnSuccess;
}

UInt32 AirportItlwm::getFeatures() const
{
    return fHalService->getDriverInfo()->supportedFeatures();
}

IOReturn AirportItlwm::setPromiscuousMode(IOEnetPromiscuousMode mode)
{
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::setMulticastMode(IOEnetMulticastMode mode)
{
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::setMulticastList(IOEthernetAddress* addr, UInt32 len)
{
    return fHalService->getDriverController()->setMulticastList(addr, len);
}

IOReturn AirportItlwm::getPacketFilters(const OSSymbol *group, UInt32 *filters) const
{
    IOReturn    rtn = kIOReturnSuccess;
    if (group == gIOEthernetWakeOnLANFilterGroup && magicPacketSupported)
        *filters = kIOEthernetWakeOnMagicPacket;
    else if (group == gIONetworkFilterGroup)
        *filters = kIOPacketFilterMulticast | kIOPacketFilterPromiscuous;
    else
        rtn = IOEthernetController::getPacketFilters(group, filters);
    return rtn;
}

SInt32 AirportItlwm::
enableFeature(IO80211FeatureCode code, void *data)
{
    if (code == kIO80211Feature80211n) {
        return 0;
    }
    return 102;
}

bool AirportItlwm::getLogPipes(CCPipe**logPipe, CCPipe**eventPipe, CCPipe**snapshotsPipe)
{
    bool ret = false;
    if (logPipe) {
        *logPipe = driverLogPipe;
        ret = true;
    }
    if (eventPipe) {
        *eventPipe = driverDataPathPipe;
        ret = true;
    }
    if (snapshotsPipe) {
        *snapshotsPipe = driverSnapshotsPipe;
        ret = true;
    }
    return ret;
}

#define APPLE80211_CAPA_AWDL_FEATURE_AUTO_UNLOCK    0x00000004
#define APPLE80211_CAPA_AWDL_FEATURE_WOW            0x00000080

IOReturn AirportItlwm::
getCARD_CAPABILITIES(OSObject *object,
                                     struct apple80211_capability_data *cd)
{
    uint32_t caps = fHalService->get80211Controller()->ic_caps;
    memset(cd, 0, sizeof(struct apple80211_capability_data));
    
    if (caps & IEEE80211_C_WEP)
        cd->capabilities[0] |= 1 << APPLE80211_CAP_WEP;
    if (caps & IEEE80211_C_RSN)
        cd->capabilities[0] |= 1 << APPLE80211_CAP_TKIP | 1 << APPLE80211_CAP_AES_CCM;
    // Disable not implemented capabilities
    // if (caps & IEEE80211_C_PMGT)
    //     cd->capabilities[0] |= 1 << APPLE80211_CAP_PMGT;
    // if (caps & IEEE80211_C_IBSS)
    //     cd->capabilities[0] |= 1 << APPLE80211_CAP_IBSS;
    // if (caps & IEEE80211_C_HOSTAP)
    //     cd->capabilities[0] |= 1 << APPLE80211_CAP_HOSTAP;
    // AES not enabled, like on Apple cards
    
    if (caps & IEEE80211_C_SHSLOT)
        cd->capabilities[1] |= 1 << (APPLE80211_CAP_SHSLOT - 8);
    if (caps & IEEE80211_C_SHPREAMBLE)
        cd->capabilities[1] |= 1 << (APPLE80211_CAP_SHPREAMBLE - 8);
    if (caps & IEEE80211_C_RSN)
        cd->capabilities[1] |= 1 << (APPLE80211_CAP_WPA1 - 8) | 1 << (APPLE80211_CAP_WPA2 - 8) | 1 << (APPLE80211_CAP_TKIPMIC - 8);
    // Disable not implemented capabilities
    // if (caps & IEEE80211_C_TXPMGT)
    //     cd->capabilities[1] |= 1 << (APPLE80211_CAP_TXPMGT - 8);
    // if (caps & IEEE80211_C_MONITOR)
    //     cd->capabilities[1] |= 1 << (APPLE80211_CAP_MONITOR - 8);
    // WPA not enabled, like on Apple cards

    cd->version = APPLE80211_VERSION;
    cd->capabilities[2] = 0xEF; // BURST, WME, SHORT_GI_40MHZ, SHORT_GI_20MHZ, WOW disabled, TSN, ?, ?
    cd->capabilities[3] = 0x2B;
    cd->capabilities[5] = 0x40;
    cd->capabilities[6] = (
//                           1 |    //MFP capable
                           0x8 |
                           0x4 |
                           0x80
                           );
    *(uint16_t *)&cd->capabilities[8] = 0x201;
//
//    cd->capabilities[2] |= 0x10;
//    cd->capabilities[5] |= 0x1;
//
//    cd->capabilities[2] |= 0x2;
//
//    cd->capabilities[3] |= 0x20;
//
//    cd->capabilities[0] |= 0x80;
//
//    cd->capabilities[3] |= 0x80;
//    cd->capabilities[4] |= 0x4;
//
//    cd->capabilities[4] |= 0x1;
//    cd->capabilities[3] |= 0x1;
//    cd->capabilities[6] |= 0x8;
//
//    cd->capabilities[3] |= 3;
//    cd->capabilities[4] |= 2;
//    cd->capabilities[6] |= 0x10;
//    cd->capabilities[5] |= 0x20;
//    cd->capabilities[5] |= 0x80;
//
//    if (cd->capabilities[6] & 0x20) {
//        cd->capabilities[2] |= 8;
//    }
//    cd->capabilities[5] |= 8;
//    cd->capabilities[8] |= 2;
//
//    cd->capabilities[11] |= (2 | 4 | 8 | 0x10 | 0x20 | 0x40 | 0x80);
    
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getDRIVER_VERSION(OSObject *object,
                                  struct apple80211_version_data *hv)
{
    if (!hv)
        return kIOReturnError;
    hv->version = APPLE80211_VERSION;
    snprintf(hv->string, sizeof(hv->string), "itlwm: %s%s fw: %s", ITLWM_VERSION, GIT_COMMIT, fHalService->getDriverInfo()->getFirmwareVersion());
    hv->string_len = strlen(hv->string);
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getHARDWARE_VERSION(OSObject *object,
                                    struct apple80211_version_data *hv)
{
    if (!hv)
        return kIOReturnError;
    hv->version = APPLE80211_VERSION;
    strncpy(hv->string, fHalService->getDriverInfo()->getFirmwareVersion(), sizeof(hv->string));
    hv->string_len = strlen(fHalService->getDriverInfo()->getFirmwareVersion());
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getCOUNTRY_CODE(OSObject *object,
                                struct apple80211_country_code_data *cd)
{
    char user_override_cc[3];
    const char *cc_fw = fHalService->getDriverInfo()->getFirmwareCountryCode();
    
    if (!cd)
        return kIOReturnError;
    cd->version = APPLE80211_VERSION;
    memset(user_override_cc, 0, sizeof(user_override_cc));
    PE_parse_boot_argn("itlwm_cc", user_override_cc, 3);
    /* user_override_cc > firmware_cc > geo_location_cc */
    strncpy((char*)cd->cc, user_override_cc[0] ? user_override_cc : ((cc_fw[0] == 'Z' && cc_fw[1] == 'Z' && geo_location_cc[0]) ? geo_location_cc : cc_fw), sizeof(cd->cc));
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setCOUNTRY_CODE(OSObject *object, struct apple80211_country_code_data *data)
{
    XYLog("%s cc=%s\n", __FUNCTION__, data->cc);
    if (data && data->cc[0] != 120 && data->cc[0] != 88) {
        memcpy(geo_location_cc, data->cc, sizeof(geo_location_cc));
        fNetIf->postMessage(APPLE80211_M_COUNTRY_CODE_CHANGED, NULL, 0, 0);
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getPOWER(OSObject *object,
                         struct apple80211_power_data *pd)
{
    if (!pd)
        return kIOReturnError;
    pd->version = APPLE80211_VERSION;
    pd->num_radios = 4;
    pd->power_state[0] = power_state;
    pd->power_state[1] = power_state;
    pd->power_state[2] = power_state;
    pd->power_state[3] = power_state;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setPOWER(OSObject *object,
                         struct apple80211_power_data *pd)
{
    if (!pd)
        return kIOReturnError;
    IOLog("itlwm: setPOWER: num_radios[%d]  power_state(0:%u  1:%u  2:%u  3:%u)\n", pd->num_radios, pd->power_state[0], pd->power_state[1], pd->power_state[2], pd->power_state[3]);
    if (pd->num_radios > 0) {
        bool isRunning = (fHalService->get80211Controller()->ic_ac.ac_if.if_flags & (IFF_UP | IFF_RUNNING)) != 0;
        if (pd->power_state[0] == 0) {
            changePowerStateToPriv(1);
            if (isRunning) {
                net80211_ifstats(fHalService->get80211Controller());
                disableAdapter(bsdInterface);
            }
        } else {
            changePowerStateToPriv(2);
            if (!isRunning)
                enableAdapter(bsdInterface);
        }
        power_state = (pd->power_state[0]);
    }
    
    return kIOReturnSuccess;
}

SInt32 AirportItlwm::apple80211_ioctl(IO80211SkywalkInterface *interface,unsigned long cmd,void *data, bool b1, bool b2)
{
    if (cmd == 349) {
        UInt8 value = 1;
        OSData *marker = OSData::withBytes(&value, sizeof(value));
        if (marker != nullptr) {
            setProperty("AIRPLAY349AppleIOCTL", marker);
            marker->release();
        }
    }

    if (!ml_at_interrupt_context())
        XYLog("%s cmd: %s b1: %d b2: %d\n", __FUNCTION__, convertApple80211IOCTLToString((unsigned int)cmd), b1, b2);
    if (!ml_at_interrupt_context())
        XYLog("AIRPLAY TRACE: cmd=%lu (%s) b1=%d b2=%d\n",
              cmd, convertApple80211IOCTLToString((unsigned int)cmd), b1, b2);

    return super::apple80211_ioctl(interface, cmd, data, b1, b2);
}

SInt32 AirportItlwm::apple80211_ioctl_set(
    IO80211VirtualInterface *interface,
    void *data,
    bool b1,
    bool b2
)
{
    struct apple80211req *req =
        reinterpret_cast<struct apple80211req *>(data);

    if (req != nullptr) {
        setProperty(
            "AIRPLAYVirtualSetSeen",
            (unsigned long long)1,
            8
        );

        setProperty(
            "AIRPLAYVirtualSetReqType",
            (unsigned long long)(uint32_t)req->req_type,
            32
        );

        setProperty(
            "AIRPLAYVirtualSetReqVal",
            (unsigned long long)(uint32_t)req->req_val,
            32
        );

        setProperty(
            "AIRPLAYVirtualSetReqLen",
            (unsigned long long)req->req_len,
            32
        );

        if (!ml_at_interrupt_context()) {
            XYLog(
                "AIRPLAY VIRTUAL IOCTL SET: req_type=%d req_val=%d req_len=%u b1=%d b2=%d\n",
                req->req_type,
                req->req_val,
                req->req_len,
                b1 ? 1 : 0,
                b2 ? 1 : 0
            );
        }
    } else if (!ml_at_interrupt_context()) {
        XYLog(
            "AIRPLAY VIRTUAL IOCTL SET: data=null b1=%d b2=%d\n",
            b1 ? 1 : 0,
            b2 ? 1 : 0
        );
    }

    SInt32 result =
        super::apple80211_ioctl_set(interface, data, b1, b2);

    if (!ml_at_interrupt_context() && req != nullptr) {
        XYLog(
            "AIRPLAY VIRTUAL IOCTL SET RESULT: req_type=%d result=%d\n",
            req->req_type,
            result
        );
    }

    return result;
}


SInt32 AirportItlwm::apple80211VirtualRequest(
    UInt request_type,
    int request_number,
    IO80211VirtualInterface *interface,
    void *data
)
{
    if (request_number == APPLE80211_IOC_SUPPORTED_CHANNELS) {
        IOLog(
            "AIRPLAY VIRTUALREQ27: type=%u request=%d interface=%p data=%p\\n",
            request_type,
            request_number,
            interface,
            data
        );

        if (interface != nullptr) {
            interface->setProperty(
                "AIRPLAYVirtualReq27Enter",
                (unsigned long long)1,
                8
            );
        }
    }

    if (request_number == 349) {
        UInt8 value = 1;
        OSData *marker = OSData::withBytes(&value, sizeof(value));
        if (marker != nullptr) {
            setProperty("AIRPLAY349VirtualRequest", marker);
            marker->release();
        }
    }

    if (!ml_at_interrupt_context() &&
        (request_number == 119 || request_number == 120)) {
        XYLog("AIRPLAY VIRTUALREQ: type=%u request=%d\n",
              request_type,
              request_number);
    }

    SInt32 channelProbeResult = super::apple80211VirtualRequest(
        request_type,
        request_number,
        interface,
        data
    );
    if (request_number == 207 || request_number == 379) {
        IOLog("AIRPLAY CHANIOCTL PROBE VIRTUAL selector=%d ret=0x%08x\n",
              request_number, (unsigned int)channelProbeResult);
    }
    return channelProbeResult;
}

SInt32 AirportItlwm::apple80211SkywalkRequest(UInt request,int cmd,IO80211SkywalkInterface *interface,void *data)
{
    if (request == 207 || request == 379 || cmd == 207 || cmd == 379) {
        IOLog("AIRPLAY CHANIOCTL PROBE SKYWALK_REQUEST request=%u cmd=%d\n", request, cmd);
    }

    if (request == 349 || cmd == 349) {
        UInt8 value = 1;
        OSData *marker = OSData::withBytes(&value, sizeof(value));
        if (marker != nullptr) {
            setProperty("AIRPLAY349Skywalk1", marker);
            marker->release();
        }
    }

    if (!ml_at_interrupt_context())
        XYLog("%s 1 cmd: %s request: %d\n", __FUNCTION__, convertApple80211IOCTLToString(cmd), request);
    return kIOReturnUnsupported;
}

SInt32 AirportItlwm::apple80211SkywalkRequest(UInt request,int cmd,IO80211SkywalkInterface *interface,void *data,void *)
{
    if (request == 349 || cmd == 349) {
        UInt8 value = 1;
        OSData *marker = OSData::withBytes(&value, sizeof(value));
        if (marker != nullptr) {
            setProperty("AIRPLAY349Skywalk2", marker);
            marker->release();
        }
    }

    if (!ml_at_interrupt_context())
        XYLog("%s 2 cmd: %s request: %d\n", __FUNCTION__, convertApple80211IOCTLToString(cmd), request);
    return kIOReturnUnsupported;
}

IOReturn AirportItlwm::enableAdapter(IONetworkInterface *netif)
{
    fHalService->enable(netif);
    watchdogTimer->setTimeoutMS(kWatchDogTimerPeriod);
    watchdogTimer->enable();
    return kIOReturnSuccess;
}

void AirportItlwm::disableAdapter(IONetworkInterface *netif)
{
    watchdogTimer->cancelTimeout();
    watchdogTimer->disable();
    fHalService->disable(netif);
}

IOReturn AirportItlwm::
tsleepHandler(OSObject* owner, void* arg0, void* arg1, void* arg2, void* arg3)
{
    AirportItlwm* dev = OSDynamicCast(AirportItlwm, owner);
    if (dev == 0)
        return kIOReturnError;
    
    if (arg1 == 0) {
        if (_fCommandGate->commandSleep(arg0, THREAD_INTERRUPTIBLE) == THREAD_AWAKENED)
            return kIOReturnSuccess;
        else
            return kIOReturnTimeout;
    } else {
        AbsoluteTime deadline;
        clock_interval_to_deadline((*(int*)arg1), kNanosecondScale, reinterpret_cast<uint64_t*> (&deadline));
        if (_fCommandGate->commandSleep(arg0, deadline, THREAD_INTERRUPTIBLE) == THREAD_AWAKENED)
            return kIOReturnSuccess;
        else
            return kIOReturnTimeout;
    }
}

bool AirportItlwm::initPCIPowerManagment(IOPCIDevice *provider)
{
    UInt16 reg16;

    reg16 = provider->configRead16(kIOPCIConfigCommand);

    reg16 |= ( kIOPCICommandBusMaster       |
               kIOPCICommandMemorySpace     |
               kIOPCICommandMemWrInvalidate );

    reg16 &= ~kIOPCICommandIOSpace;  // disable I/O space

    provider->configWrite16( kIOPCIConfigCommand, reg16 );
    provider->findPCICapability(kIOPCIPowerManagementCapability,
                                &pmPCICapPtr);
    if (pmPCICapPtr) {
        UInt16 pciPMCReg = provider->configRead32( pmPCICapPtr ) >> 16;
        if (pciPMCReg & kPCIPMCPMESupportFromD3Cold)
            magicPacketSupported = true;
        provider->configWrite16((pmPCICapPtr + 4), 0x8000 );
        IOSleep(10);
    }
    return true;
}

static IOPMPowerState powerStateArray[kPowerStateCount] =
{
    {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {1, kIOPMDeviceUsable, kIOPMPowerOn, kIOPMPowerOn, 0, 0, 0, 0, 0, 0, 0, 0}
};

void AirportItlwm::unregistPM()
{
    if (powerOffThreadCall) {
        thread_call_free(powerOffThreadCall);
        powerOffThreadCall = NULL;
    }
    if (powerOnThreadCall) {
        thread_call_free(powerOnThreadCall);
        powerOnThreadCall = NULL;
    }
}

IOReturn AirportItlwm::setPowerState(unsigned long powerStateOrdinal, IOService *policyMaker)
{
    IOReturn result = IOPMAckImplied;
    
    if (pmPowerState == powerStateOrdinal)
        return result;
    switch (powerStateOrdinal) {
        case kPowerStateOff:
            if (powerOffThreadCall) {
                retain();
                if (thread_call_enter(powerOffThreadCall))
                    release();
                result = 5000000;
            }
            break;
        case kPowerStateOn:
            if (powerOnThreadCall) {
                retain();
                if (thread_call_enter(powerOnThreadCall))
                    release();
                result = 5000000;
            }
            break;
            
        default:
            break;
    }
    return result;
}

IOReturn AirportItlwm::setWakeOnMagicPacket(bool active)
{
    magicPacketEnabled = active;
    return kIOReturnSuccess;
}

static void handleSetPowerStateOff(thread_call_param_t param0,
                             thread_call_param_t param1)
{
    AirportItlwm *self = (AirportItlwm *)param0;

    if (param1 == 0)
    {
        self->getCommandGate()->runAction((IOCommandGate::Action)
                                           handleSetPowerStateOff,
                                           (void *) 1);
    }
    else
    {
        self->setPowerStateOff();
        self->release();
    }
}

static void handleSetPowerStateOn(thread_call_param_t param0,
                            thread_call_param_t param1)
{
    AirportItlwm *self = (AirportItlwm *) param0;

    if (param1 == 0)
    {
        self->getCommandGate()->runAction((IOCommandGate::Action)
                                           handleSetPowerStateOn,
                                           (void *) 1);
    }
    else
    {
        self->setPowerStateOn();
        self->release();
    }
}

IOReturn AirportItlwm::registerWithPolicyMaker(IOService *policyMaker)
{
    IOReturn ret;
    
    pmPowerState = kPowerStateOn;
    pmPolicyMaker = policyMaker;
    
    powerOffThreadCall = thread_call_allocate(
                                            (thread_call_func_t)handleSetPowerStateOff,
                                            (thread_call_param_t)this);
    powerOnThreadCall  = thread_call_allocate(
                                            (thread_call_func_t)handleSetPowerStateOn,
                                              (thread_call_param_t)this);
    ret = pmPolicyMaker->registerPowerDriver(this,
                                             powerStateArray,
                                             kPowerStateCount);
    return ret;
}

void AirportItlwm::setPowerStateOff()
{
    XYLog("%s\n", __FUNCTION__);
    pmPowerState = kPowerStateOff;
    disableAdapter(bsdInterface);
    pmPolicyMaker->acknowledgeSetPowerState();
}

void AirportItlwm::setPowerStateOn()
{
    XYLog("%s\n", __FUNCTION__);
    pmPowerState = kPowerStateOn;
    pmPolicyMaker->acknowledgeSetPowerState();
}
