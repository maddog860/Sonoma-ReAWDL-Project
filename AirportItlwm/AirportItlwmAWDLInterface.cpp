#include "AirportItlwmAWDLInterface.hpp"
#include <libkern/OSByteOrder.h>
#include <kern/thread.h> /* NOMONITOR: current_thread() */
#include <kern/clock.h> /* PSFTX: clock_get_uptime() */
#include "AirportItlwmV2.hpp"

/*
 * Airport/Apple80211.h already supplies AirportItlwm's private
 * IOSkywalkPacketBufferPool declaration.  Prevent MacKernelSDK's
 * duplicate pool header from redefining that class when the concrete
 * queue headers include it internally.
 */
#ifndef _IOSKYWALKPACKETBUFFERPOOL_H
#define _IOSKYWALKPACKETBUFFERPOOL_H
#endif

#include <skywalk/packet/os_packet.h>

#include <IOKit/skywalk/IOSkywalkPacketQueue.h>
#include <IOKit/skywalk/IOSkywalkPacketBuffer.h>
#include <IOKit/skywalk/IOSkywalkMemorySegment.h>
#include <IOKit/skywalk/IOSkywalkTxSubmissionQueue.h>
#include <IOKit/skywalk/IOSkywalkTxCompletionQueue.h>
#include <IOKit/skywalk/IOSkywalkRxSubmissionQueue.h>
#include <IOKit/skywalk/IOSkywalkRxCompletionQueue.h>
#include <net/kpi_interface.h>

extern struct ether_addr gAirplayAWDLAddress;
extern bool gAirplayAWDLAddressValid;

static IO80211VirtualInterface *gAirplayCompanionP2P = nullptr;


/* UMI-DIAG-V1: direct endpoints cover Apple's internal route, which bypasses
 * handleIoctl(). These counters do not generate any traffic or completions. */
static volatile UInt32 gUmi149Calls = 0, gUmi69Calls = 0;
static volatile UInt32 gUmi69Acked = 0, gUmi69Failed = 0, gUmi69Invalid = 0;

static void
airplayUmiObserveStatus(IOService *service, const void *data, unsigned long length)
{
    const UInt32 count = __sync_add_and_fetch(&gUmi69Calls, 1);
    service->setProperty("AIRPLAYUmi69Calls", (unsigned long long)count, 32);
    /* Native event 69 carries MAC[6]+status. Apple also passes length=0 for
     * this fixed-format event (BCM callback at 0xffffff8001687c15).
     * Reject an explicitly short nonzero length; preserve superclass dispatch. */
    if (data == nullptr || (length != 0 && length < 7)) {
        const UInt32 invalid = __sync_add_and_fetch(&gUmi69Invalid, 1);
        service->setProperty("AIRPLAYUmi69Invalid", (unsigned long long)invalid, 32);
        return;
    }
    UInt8 record[16] = {};
    const UInt32 version = 1;
    memcpy(record, &version, 4);
    memcpy(record + 4, &count, 4);
    memcpy(record + 8, data, 7);
    OSData *sample = OSData::withBytes(record, sizeof(record));
    if (sample != nullptr) {
        service->setProperty("AIRPLAYUmi69Last", sample);
        sample->release();
    }
    const UInt32 total = record[14] == 0
        ? __sync_add_and_fetch(&gUmi69Acked, 1)
        : __sync_add_and_fetch(&gUmi69Failed, 1);
    service->setProperty(record[14] == 0 ? "AIRPLAYUmi69Acked" : "AIRPLAYUmi69Failed",
                         (unsigned long long)total, 32);
}

static ifnet_t gAirplayAWDLBSDIfnet = nullptr;
static volatile UInt32 gAirplayAWDLSetLLAddrGeneration = 0;
static volatile SInt32 gAirplayAWDLSetLLAddrLastResult = -1;

static volatile UInt32 gAirplayAWDLPendingPacketsHits = 0;
static volatile UInt32 gAirplayAWDLPacketSpaceHits = 0;
static volatile UInt32 gAirplayAWDLTriggerMcastHits = 0;
static volatile UInt32 gAirplayAWDLP2PMcastHits = 0;

OSDefineMetaClassAndStructors(
    AirportItlwmAWDLInterface,
    IO80211AWDLProtocol
)



/*
 * Sonoma AWDL schedule cache.
 *
 * Runtime capture proves the schedule payload uses:
 *   bytes  0..11 : header
 *   bytes 12..   : apple80211_channel records
 *
 * Each active record is 12 bytes:
 *   UInt32 version
 *   UInt32 channel
 *   UInt32 flags
 *
 * Diagnostic/cache only.  Nothing here programs the Intel firmware.
 */
struct AirplayAWDLScheduleCache
{
    UInt32 generation;

    UInt8 valid;
    UInt8 armed;

    UInt32 version;

    UInt8 length;
    UInt8 encoding;
    UInt8 stepCount;
    UInt8 duplicateCount;
    UInt8 fillChannel;

    UInt32 channels[16];
    UInt32 flags[16];
};

static AirplayAWDLScheduleCache
gAirplayAWDLScheduleCache = {};

/* AWPROBE-20261015: the sequence entry IO80211 will check for this AW number (same formula as
 * IO80211AWDLPeerManager::reportDataPathEvents event 41). Read-only. */
extern "C" bool
AirportItlwmAWDLScheduleSlot(UInt32 awNumber, UInt32 *slot, UInt32 *chan, UInt32 *flags,
                             UInt32 *len, UInt32 *dup)
{
    if (slot == nullptr || chan == nullptr || flags == nullptr || len == nullptr || dup == nullptr)
        return false;
    if (!gAirplayAWDLScheduleCache.valid || gAirplayAWDLScheduleCache.length == 0 ||
        gAirplayAWDLScheduleCache.length > 16)
        return false;
    const UInt32 L = gAirplayAWDLScheduleCache.length;
    /* AWMATCH2: IO80211 divides by raw[7]+1 (cache field 'stepCount'), not raw[8] */
    const UInt32 d = (UInt32)gAirplayAWDLScheduleCache.stepCount + 1U;
    UInt32 s = (UInt32)(UInt16)((awNumber % (L * d)) / d);
    if (s >= 16)
        return false;
    *slot = s;
    *chan = gAirplayAWDLScheduleCache.channels[s];
    *flags = gAirplayAWDLScheduleCache.flags[s];
    *len = L;
    *dup = gAirplayAWDLScheduleCache.stepCount;   /* AWMATCH2: value IO80211 uses (raw[7]) */
    return true;
}

/* HOPPLAN-20261015: how many slots of macOS's AWDL channel sequence use `channel`. */
extern "C" bool
AirportItlwmAWDLScheduleShare(UInt32 channel, UInt32 *slots, UInt32 *length)
{
    if (slots == nullptr || length == nullptr || !gAirplayAWDLScheduleCache.valid ||
        gAirplayAWDLScheduleCache.length == 0 || gAirplayAWDLScheduleCache.length > 16)
        return false;
    UInt32 n = 0;
    for (unsigned int i = 0; i < gAirplayAWDLScheduleCache.length; i++)
        if ((gAirplayAWDLScheduleCache.channels[i] & 0xff) == channel)
            n++;
    *slots = n;
    *length = gAirplayAWDLScheduleCache.length;
    return true;
}

/*
 * PSFTX-20261015: AWDL presence/sync frame (PSF) builder.
 *
 * IO80211AWDLPeerManager::updateSyncFrameTemplate() hands over only the TLVs it owns
 * (service params, election params v2, data-path state, HT caps, version, ...). On
 * Broadcom the firmware wraps them and adds the timing parts. Here the driver does:
 *   802.11 header  A1 broadcast, A2 awdl0's current address, A3 AWDL BSSID 00:25:00:ff:94:73
 *   AWDL header    7f 00:17:f2 08 | version 0x10 | subtype 0 (PSF) | 0 | phy_tx | target_tx
 *   TLV 0x04       synchronization parameters (+ channel sequence), values from IO80211's
 *                  own ioctls (sync params, master channel, advertisers master, schedule)
 *   TLV 0x12       channel sequence
 *   IO80211's template TLVs, unchanged
 * Layouts follow the public AWDL descriptions (OWL); AIRPLAYPsfTxSample / AIRPLAYPsfRxSample
 * keep one sent and one received PSF for byte-level comparison.
 */
static UInt16 gAirplayPsfAWLength = 16;
static UInt16 gAirplayPsfAWPeriod = 16;
static UInt16 gAirplayPsfExtLength = 16;
static UInt16 gAirplayPsfSyncFramePeriod = 110;
static UInt8 gAirplayPsfMasterChannel = 0;
static UInt8 gAirplayPsfMaster[6] = {};
static bool gAirplayPsfMasterValid = false;
static UInt8 gAirplayPsfSelf[6] = {};
static volatile bool gAirplayPsfSelfValid = false;
static UInt16 gAirplayPsfSeqCtl = 0;
static UInt16 gAirplayPsfAwSeq = 0;
static volatile UInt32 gAirplayPsfTxSampled = 0;

/*
 * PSFSYNC-20261016: AWDL timing + election in the PSF (see PSFSYNC-20261016-patch.py).
 * Timeline model (OWL awdl_sync_*): extended AW = 4 AWs of 16 TU = 64 TU; tx counter = TU to the next
 * extended AW; aw_seq = current AW number. One writer (RX), readers (PSF build) use a generation counter.
 */
#define PSFSYNC_AW_TU      16ULL
#define PSFSYNC_EAW_TU     64ULL
#define PSFSYNC_TU_US      1024ULL
#define PSFSYNC_EAW_US     (PSFSYNC_EAW_TU * PSFSYNC_TU_US)
#define PSFSYNC_FOLLOW_US  4000000ULL
#define PSFSYNC_RESET_US   20000LL

struct AirplayPsfSyncState {
    UInt64 startUs;       /* uptime (us) at the start of an extended AW */
    UInt16 aw;            /* AW number at startUs (multiple of 4) */
    UInt8  peer[6];       /* peer whose timing we follow */
    UInt8  master[6];     /* that peer's master */
    UInt32 masterMetric;
    UInt32 masterCounter;
    UInt32 distance;      /* that peer's distance to the master */
    UInt64 lastUs;        /* last frame from that peer */
    bool   valid;
};
static AirplayPsfSyncState gPsfSync = {};
static volatile UInt32 gPsfSyncGen = 0;
static int gPsfSyncOff = -1;
static int gPsfSyncExtraOff = -1;
static UInt64 gPsfOwnStartUs = 0;
static bool gPsfOwnValid = false;
static volatile UInt32 gPsfSyncSampled = 0;
static UInt64 gPsfSyncLastPublishUs = 0;
static UInt32 gPsfSyncRxParsed = 0;
static UInt32 gPsfSyncRxBad = 0;
static UInt32 gPsfSyncRxSelfMaster = 0;
static UInt32 gPsfSyncRxIgnored = 0;
static UInt32 gPsfSyncSwitches = 0;
static UInt32 gPsfSyncResets = 0;
static UInt32 gPsfSyncAdjEarly = 0;
static UInt32 gPsfSyncAdjLate = 0;
static UInt32 gPsfSyncLastErrUs = 0;
static UInt32 gPsfSyncTxFollowing = 0;
static UInt32 gPsfSyncTxOwnClock = 0;
static UInt32 gPsfSyncV2Patched = 0;
static UInt32 gPsfSyncV2Missing = 0;
static UInt32 gPsfSyncV1Added = 0;
static UInt32 gPsfSyncTreeAdded = 0;
static UInt32 gPsfSyncLastTxc = 0;
static UInt32 gPsfSyncLastAwSeq = 0;
static UInt32 gPsfSyncLastPeerTxc = 0;
static UInt32 gPsfSyncLastPeerSeq = 0;
static UInt32 gPsfSyncSelfMetric = 0;

static inline UInt64
airplayPsfUptimeUs(void)
{
    uint64_t a = 0, ns = 0;
    clock_get_uptime(&a);
    absolutetime_to_nanoseconds(a, &ns);
    return ns / 1000ULL;
}

static inline UInt16
airplayPsfGet16(const uint8_t *p)
{
    return (UInt16)(p[0] | (p[1] << 8));
}

static inline UInt32
airplayPsfGet32(const uint8_t *p)
{
    return (UInt32)p[0] | ((UInt32)p[1] << 8) | ((UInt32)p[2] << 16) | ((UInt32)p[3] << 24);
}

static const uint8_t *
airplayPsfFindTlv(const uint8_t *b, size_t len, UInt8 type, size_t *vlen)
{
    size_t i = 0;
    while (b != nullptr && i + 3 <= len) {
        const size_t l = (size_t)airplayPsfGet16(b + i + 1);
        if (i + 3 + l > len)
            break;
        if (b[i] == type) {
            if (vlen != nullptr)
                *vlen = l;
            return b + i + 3;
        }
        i += 3 + l;
    }
    return nullptr;
}

static void
airplayPsfSyncInitSwitches(void)
{
    if (gPsfSyncOff < 0) {
        int v = 0;
        gPsfSyncOff = PE_parse_boot_argn("-awdlpsfsyncoff", &v, sizeof(v)) ? 1 : 0;
    }
    if (gPsfSyncExtraOff < 0) {
        int v = 0;
        gPsfSyncExtraOff = PE_parse_boot_argn("-awdlpsfextraoff", &v, sizeof(v)) ? 1 : 0;
    }
}

static bool
airplayPsfSyncSnapshot(AirplayPsfSyncState *out)
{
    for (int i = 0; i < 4; i++) {
        const UInt32 g1 = gPsfSyncGen;
        __sync_synchronize();
        if (g1 & 1)
            continue;
        memcpy(out, &gPsfSync, sizeof(*out));
        __sync_synchronize();
        if (gPsfSyncGen == g1)
            return true;
    }
    return false;
}

/* Called for every received AWDL action frame (body starts at the 0x7f category byte). */
extern "C" void
AirportItlwmAWDLSyncObserve(const uint8_t *sa, const uint8_t *body, size_t len)
{
    airplayPsfSyncInitSwitches();
    if (gPsfSyncOff || sa == nullptr || body == nullptr)
        return;
    const UInt64 nowUs = airplayPsfUptimeUs();
    if (len < 16 + 3 || body[0] != 0x7f || body[1] != 0x00 || body[2] != 0x17 ||
        body[3] != 0xf2 || body[4] != 0x08)
        return;
    if (body[6] != 0 && body[6] != 3)   /* PSF / MIF only */
        return;
    if (gAirplayPsfSelfValid && memcmp(sa, gAirplayPsfSelf, 6) == 0)
        return;

    size_t spLen = 0, v2Len = 0;
    const uint8_t *sp = airplayPsfFindTlv(body + 16, len - 16, 0x04, &spLen);
    const uint8_t *v2 = airplayPsfFindTlv(body + 16, len - 16, 0x18, &v2Len);
    if (sp == nullptr || spLen < 33) {
        gPsfSyncRxBad++;
        return;
    }
    if (v2 != nullptr && v2Len < 28)
        v2 = nullptr;
    const UInt16 txc = airplayPsfGet16(sp + 1);
    const UInt16 awPeriod = airplayPsfGet16(sp + 5);
    const UInt8 presence = sp[27];
    const UInt16 seq = airplayPsfGet16(sp + 29);
    const uint8_t *master = sp + 21;
    if (txc == 0 || txc > PSFSYNC_EAW_TU || awPeriod != PSFSYNC_AW_TU || presence != 4) {
        gPsfSyncRxBad++;
        return;
    }
    gPsfSyncRxParsed++;
    gPsfSyncLastPeerTxc = txc;
    gPsfSyncLastPeerSeq = seq;
    if (gAirplayPsfSelfValid && memcmp(master, gAirplayPsfSelf, 6) == 0) {
        gPsfSyncRxSelfMaster++;   /* this peer follows us: never follow it back */
        return;
    }
    const UInt32 mm = v2 ? airplayPsfGet32(v2 + 20) : 0;
    const UInt32 mc = v2 ? airplayPsfGet32(v2 + 12) : 0;
    UInt32 dist = v2 ? airplayPsfGet32(v2 + 16) : 0;
    if (dist > 16)
        dist = 16;

    const bool same = gPsfSync.valid && memcmp(sa, gPsfSync.peer, 6) == 0;
    const bool fresh = gPsfSync.valid && (nowUs - gPsfSync.lastUs) < PSFSYNC_FOLLOW_US;
    bool switchPeer = false;
    if (!same) {
        if (!fresh || mm > gPsfSync.masterMetric ||
            (mm == gPsfSync.masterMetric && dist < gPsfSync.distance))
            switchPeer = true;
        else {
            gPsfSyncRxIgnored++;
            return;
        }
    }

    const SInt64 eaw = (SInt64)PSFSYNC_EAW_US;
    const UInt64 candStart = nowUs + (UInt64)txc * PSFSYNC_TU_US - (UInt64)eaw;
    const UInt16 candAw = (UInt16)(seq & 0xfffc);
    UInt64 newStart = candStart;
    if (!switchPeer && gPsfSync.valid) {
        const SInt16 dAw = (SInt16)(UInt16)(candAw - gPsfSync.aw);
        const SInt64 proj = (SInt64)gPsfSync.startUs + (SInt64)(dAw / 4) * eaw;
        const SInt64 err = (SInt64)candStart - proj;
        const SInt64 aerr = err < 0 ? -err : err;
        gPsfSyncLastErrUs = aerr > 0x7fffffffLL ? 0x7fffffffU : (UInt32)aerr;
        if (aerr > PSFSYNC_RESET_US) {
            gPsfSyncResets++;
        } else if (err < 0) {
            gPsfSyncAdjEarly++;                     /* less RX latency: take it */
        } else {
            newStart = (UInt64)(proj + err / 8);    /* later: drift slowly */
            gPsfSyncAdjLate++;
        }
    }

    gPsfSyncGen++;
    __sync_synchronize();
    if (switchPeer) {
        memcpy(gPsfSync.peer, sa, 6);
        gPsfSyncSwitches++;
    }
    gPsfSync.startUs = newStart;
    gPsfSync.aw = candAw;
    memcpy(gPsfSync.master, master, 6);
    gPsfSync.masterMetric = mm;
    gPsfSync.masterCounter = mc;
    gPsfSync.distance = dist;
    gPsfSync.lastUs = nowUs;
    gPsfSync.valid = true;
    __sync_synchronize();
    gPsfSyncGen++;
}

/*
 * AWALIGN-20261016: AWDL slot clock. Channel sequence = 16 entries, each 4 AWs (64 TU = 65.536 ms),
 * period 1.048576 s, slot = (aw / 4) % 16. Clock = followed peer's timeline (PSFSYNC) or our own.
 */
#define AWALIGN_AW_US   (PSFSYNC_AW_TU * PSFSYNC_TU_US)   /* 16384 */
#define AWALIGN_SLOT_US (4ULL * AWALIGN_AW_US)            /* 65536 */

static bool
airplayAwalignClock(UInt64 *startUs, UInt16 *aw)
{
    AirplayPsfSyncState snap = {};
    if (airplayPsfSyncSnapshot(&snap) && snap.valid) {
        *startUs = snap.startUs;
        *aw = snap.aw;
        return true;
    }
    if (gPsfOwnValid) {
        *startUs = gPsfOwnStartUs;
        *aw = 0;
        return true;
    }
    return false;
}

static UInt16
airplayAwalignCurAw(UInt64 nowUs, UInt64 startUs, UInt16 aw, SInt64 *awStartUs)
{
    const SInt64 per = (SInt64)AWALIGN_AW_US;
    const SInt64 d = (SInt64)nowUs - (SInt64)startUs;
    const SInt64 n = d >= 0 ? d / per : -(((-d) + per - 1) / per);
    if (awStartUs != nullptr)
        *awStartUs = (SInt64)startUs + n * per;
    return (UInt16)((SInt64)aw + n);
}

extern "C" UInt32
AirportItlwmAWDLSlotNow(void)
{
    UInt64 st = 0;
    UInt16 aw = 0;
    if (!airplayAwalignClock(&st, &aw))
        return 0xff;
    const UInt16 cur = airplayAwalignCurAw(airplayPsfUptimeUs(), st, aw, nullptr);
    return (UInt32)((cur / 4U) % 16U);
}

static inline bool
airplayAwalignSlotOn(unsigned int slot, UInt32 chan)
{
    return gAirplayAWDLScheduleCache.valid && gAirplayAWDLScheduleCache.length == 16 &&
           (gAirplayAWDLScheduleCache.channels[slot % 16] & 0xff) == chan;
}

/* Next run of schedule slots on listenChan starting >= minDelayMs (+lead) from now. */
extern "C" bool
AirportItlwmAWDLNextListen(UInt32 listenChan, UInt32 leadUs, UInt32 minDelayMs, UInt32 maxSlots,
                           UInt32 *delayMs, UInt32 *durMs, UInt32 *firstSlot, UInt32 *nSlots)
{
    if (listenChan == 0 || delayMs == nullptr || durMs == nullptr || firstSlot == nullptr ||
        nSlots == nullptr || maxSlots == 0 || !gAirplayAWDLScheduleCache.valid ||
        gAirplayAWDLScheduleCache.length != 16)
        return false;
    UInt64 st = 0;
    UInt16 aw = 0;
    if (!airplayAwalignClock(&st, &aw))
        return false;
    const UInt64 now = airplayPsfUptimeUs();
    SInt64 curStart = 0;
    const UInt16 cur = airplayAwalignCurAw(now, st, aw, &curStart);
    const UInt16 k0 = (UInt16)(cur & 0xfffcU);
    const SInt64 t0 = curStart - (SInt64)((UInt16)(cur - k0)) * (SInt64)AWALIGN_AW_US;
    const unsigned int s0 = (unsigned int)((k0 / 4U) % 16U);
    const SInt64 earliest = (SInt64)now + (SInt64)minDelayMs * 1000 + (SInt64)leadUs;
    for (unsigned int j = 0; j < 40; j++) {
        const unsigned int slot = (s0 + j) % 16;
        const SInt64 tj = t0 + (SInt64)j * (SInt64)AWALIGN_SLOT_US;
        if (tj < earliest || !airplayAwalignSlotOn(slot, listenChan))
            continue;
        unsigned int n = 1;
        while (n < maxSlots && airplayAwalignSlotOn(slot + n, listenChan))
            n++;
        *delayMs = (UInt32)((tj - (SInt64)leadUs - (SInt64)now) / 1000);
        *durMs = (UInt32)(((UInt64)n * AWALIGN_SLOT_US + leadUs + 2000) / 1000);
        *firstSlot = slot;
        *nSlots = n;
        return true;
    }
    return false;
}

extern "C" bool
AirportItlwmAWDLSelfAddr(uint8_t *out)
{
    if (out == nullptr || !gAirplayPsfSelfValid)
        return false;
    memcpy(out, gAirplayPsfSelf, 6);
    return true;
}

/* MACFOLLOW-20261015: awdl0's current link-layer address (macOS rotates it). */
extern "C" bool
AirportItlwmAWDLCurrentAddr(uint8_t *out)
{
    if (out == nullptr || gAirplayAWDLBSDIfnet == nullptr)
        return false;
    return ifnet_lladdr_copy_bytes(gAirplayAWDLBSDIfnet, out, 6) == 0;
}

static inline void
airplayPsfPut16(uint8_t *p, UInt16 v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)(v >> 8);
}

static inline void
airplayPsfPut32(uint8_t *p, UInt32 v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)(v >> 24);
}

/* Channel sequence: count-1, encoding 3 (channel + operating class), dup 0, step 3, fill 0xffff, 16 x 2 bytes. */
static size_t
airplayPsfPutChanSeq(uint8_t *p)
{
    size_t n = 0;
    p[n++] = 15;
    p[n++] = 3;
    p[n++] = 0;
    p[n++] = 3;
    airplayPsfPut16(p + n, 0xffff);
    n += 2;
    const bool haveSched = gAirplayAWDLScheduleCache.valid && gAirplayAWDLScheduleCache.length > 0;
    for (unsigned int i = 0; i < 16; i++) {
        UInt32 ch = 149;
        if (haveSched)
            ch = (i < gAirplayAWDLScheduleCache.length) ? (gAirplayAWDLScheduleCache.channels[i] & 0xff) : 0;
        p[n++] = (uint8_t)ch;
        p[n++] = (ch == 0) ? 0x00 : (ch <= 14 ? 0x51 : 0x80);
    }
    return n; /* 38 */
}

/* PSFENC-20261016: Apple's TLV 0x04 channel sequence, encoding 1 (legacy: flags, centre channel). */
static int gPsfEnc3 = -1;
static UInt32 gPsfEncUnmapped = 0;
static bool
airplayPsfEncLegacyOn(void)
{
    if (gPsfEnc3 < 0) {
        int v = 0;
        gPsfEnc3 = PE_parse_boot_argn("-awdlpsfenc3", &v, sizeof(v)) ? 1 : 0;
    }
    return gPsfEnc3 == 0;
}

static size_t
airplayPsfPutChanSeqLegacy(uint8_t *p)
{
    size_t n = 0;
    p[n++] = 15;
    p[n++] = 1;
    p[n++] = 0;
    p[n++] = 3;
    airplayPsfPut16(p + n, 0xffff);
    n += 2;
    const bool haveSched = gAirplayAWDLScheduleCache.valid && gAirplayAWDLScheduleCache.length > 0;
    for (unsigned int i = 0; i < 16; i++) {
        UInt32 ch = 149;
        if (haveSched)
            ch = (i < gAirplayAWDLScheduleCache.length) ? (gAirplayAWDLScheduleCache.channels[i] & 0xff) : 0;
        uint8_t fl = 0, cc = 0;
        if (ch == 0) {
            fl = 0; cc = 0;
        } else if (ch <= 14) {
            fl = 0x2b; cc = (uint8_t)ch;
        } else if (ch == 149 || ch == 157 || ch == 36 || ch == 44 || ch == 52 || ch == 60 ||
                   ch == 100 || ch == 108 || ch == 116 || ch == 124 || ch == 132 || ch == 140) {
            fl = 0x1d; cc = (uint8_t)(ch + 2);
        } else {
            gPsfEncUnmapped++;
            fl = 0; cc = 0;
        }
        p[n++] = fl;
        p[n++] = cc;
    }
    return n; /* 38 */
}

extern "C" size_t
AirportItlwmAWDLBuildPSF(IOEthernetController *controller, uint8_t *out, size_t outMax, UInt32 *why)
{
    UInt32 dummy = 0;
    if (why == nullptr)
        why = &dummy;
    *why = 0;
    AirportItlwm *owner = OSDynamicCast(AirportItlwm, controller);
    if (owner == nullptr || out == nullptr) {
        *why = 1;
        return 0;
    }
    if (owner->syncFrameTemplate == nullptr || owner->syncFrameTemplateLength == 0) {
        *why = 2;
        return 0;
    }
    if (gAirplayAWDLBSDIfnet == nullptr) {
        *why = 3;
        return 0;
    }
    uint8_t self[6];
    if (ifnet_lladdr_copy_bytes(gAirplayAWDLBSDIfnet, self, sizeof(self)) != 0) {
        *why = 4;
        return 0;
    }
    memcpy(gAirplayPsfSelf, self, 6);
    gAirplayPsfSelfValid = true;

    const size_t tplLen = owner->syncFrameTemplateLength;
    const size_t need = 24 + 16 + (3 + 73) + (3 + 21) + (3 + 41) + tplLen + (3 + 12); /* PSFSYNC */
    if (need > outMax) {
        *why = 5;
        return 0;
    }

    uint64_t nowAbs = 0, nowNs = 0;
    clock_get_uptime(&nowAbs);
    absolutetime_to_nanoseconds(nowAbs, &nowNs);
    const UInt32 nowUs = (UInt32)(nowNs / 1000ULL);
    UInt16 awSeq = gAirplayPsfAwSeq++;
    UInt16 txCounter = gAirplayPsfAWPeriod;
    /* PSFSYNC-20261016: tx counter / AW number from the followed timeline (or our own steady clock) */
    airplayPsfSyncInitSwitches();
    AirplayPsfSyncState sync = {};
    bool following = false;
    if (!gPsfSyncOff) {
        const UInt64 nowUs64 = nowNs / 1000ULL;
        const bool haveSync = airplayPsfSyncSnapshot(&sync) && sync.valid;
        following = haveSync && (nowUs64 - sync.lastUs) < PSFSYNC_FOLLOW_US;
        UInt64 start;
        UInt16 aw;
        if (haveSync) {
            start = sync.startUs;
            aw = sync.aw;
        } else {
            if (!gPsfOwnValid) {
                gPsfOwnStartUs = nowUs64;
                gPsfOwnValid = true;
            }
            start = gPsfOwnStartUs;
            aw = 0;
        }
        if (start > nowUs64) {
            const UInt64 k = (start - nowUs64 + PSFSYNC_EAW_US - 1) / PSFSYNC_EAW_US;
            start -= k * PSFSYNC_EAW_US;
            aw = (UInt16)(aw - 4 * k);
        }
        const UInt64 since = nowUs64 - start;
        const UInt64 eaws = since / PSFSYNC_EAW_US;
        const UInt64 withinTu = (since % PSFSYNC_EAW_US) / PSFSYNC_TU_US;   /* 0..63 */
        txCounter = (UInt16)(PSFSYNC_EAW_TU - withinTu);                    /* 1..64 */
        awSeq = (UInt16)(aw + 4 * eaws + withinTu / PSFSYNC_AW_TU);
        if (following)
            gPsfSyncTxFollowing++;
        else
            gPsfSyncTxOwnClock++;
        gPsfSyncLastTxc = txCounter;
        gPsfSyncLastAwSeq = awSeq;
    }

    size_t p = 0;
    /* 802.11 management header, subtype action */
    out[p++] = 0xd0;
    out[p++] = 0x00;
    out[p++] = 0x00;
    out[p++] = 0x00;
    memset(out + p, 0xff, 6);
    p += 6;
    memcpy(out + p, self, 6);
    p += 6;
    static const uint8_t awdlBssid[6] = { 0x00, 0x25, 0x00, 0xff, 0x94, 0x73 };
    memcpy(out + p, awdlBssid, 6);
    p += 6;
    airplayPsfPut16(out + p, (UInt16)((gAirplayPsfSeqCtl++ & 0x0fff) << 4));
    p += 2;

    /* AWDL action header */
    out[p++] = 0x7f;
    out[p++] = 0x00;
    out[p++] = 0x17;
    out[p++] = 0xf2;
    out[p++] = 0x08;
    out[p++] = 0x10;
    out[p++] = 0x00; /* PSF */
    out[p++] = 0x00;
    airplayPsfPut32(out + p, nowUs); /* phy_tx */
    p += 4;
    airplayPsfPut32(out + p, nowUs); /* target_tx */
    p += 4;

    /* TLV 0x04 synchronization parameters, value length 73 */
    const UInt8 masterChan = gAirplayPsfMasterChannel != 0 ? gAirplayPsfMasterChannel : 149;
    UInt8 nextChan = masterChan;
    if (gAirplayAWDLScheduleCache.valid && gAirplayAWDLScheduleCache.length > 0) {
        const unsigned int next = gAirplayAWDLScheduleCache.length == 16 /* AWALIGN: 4 AWs per slot */
            ? (unsigned int)((((UInt16)(awSeq + 1U)) / 4U) % 16U)
            : (awSeq + 1U) % gAirplayAWDLScheduleCache.length;
        const UInt8 c = (UInt8)(gAirplayAWDLScheduleCache.channels[next] & 0xff);
        if (c != 0)
            nextChan = c;
    }
    out[p++] = 0x04;
    airplayPsfPut16(out + p, 73);
    p += 2;
    const size_t syncStart = p;
    out[p++] = nextChan;                              /* next AW channel */
    airplayPsfPut16(out + p, txCounter);              /* tx counter (TU to next extended AW) PSFSYNC */
    p += 2;
    out[p++] = masterChan;                            /* master channel */
    out[p++] = 0;                                     /* guard time */
    airplayPsfPut16(out + p, gAirplayPsfAWPeriod);    /* AW period */
    p += 2;
    airplayPsfPut16(out + p, gAirplayPsfSyncFramePeriod); /* action frame period */
    p += 2;
    airplayPsfPut16(out + p, 0x1800);                 /* awdl flags */
    p += 2;
    airplayPsfPut16(out + p, gAirplayPsfExtLength);   /* AW extension length */
    p += 2;
    airplayPsfPut16(out + p, gAirplayPsfAWLength);    /* AW common length */
    p += 2;
    airplayPsfPut16(out + p, 0);                      /* remaining AW length */
    p += 2;
    out[p++] = 3;                                     /* min ext */
    out[p++] = 3;                                     /* max ext multicast */
    out[p++] = 3;                                     /* max ext unicast */
    out[p++] = 3;                                     /* max ext AF */
    memcpy(out + p, following ? sync.master : (gAirplayPsfMasterValid ? gAirplayPsfMaster : self), 6); /* master address (PSFSYNC) */
    p += 6;
    out[p++] = 4;                                     /* presence mode */
    out[p++] = 0;
    airplayPsfPut16(out + p, awSeq);                  /* AW sequence number */
    p += 2;
    airplayPsfPut16(out + p, 0);                      /* AP beacon alignment delta */
    p += 2;
    p += airplayPsfEncLegacyOn() ? airplayPsfPutChanSeqLegacy(out + p) /* PSFENC */
                                 : airplayPsfPutChanSeq(out + p);
    out[p++] = 0;
    out[p++] = 0;
    if (p - syncStart != 73) {
        *why = 6;
        return 0;
    }

    /* PSFSYNC-20261016: election parameters v1 (TLV 0x05), consistent with v2 */
    size_t tplV2Len = 0;
    const uint8_t *tplV2 = airplayPsfFindTlv(owner->syncFrameTemplate, tplLen, 0x18, &tplV2Len);
    const UInt32 selfMetric = (tplV2 != nullptr && tplV2Len >= 28) ? airplayPsfGet32(tplV2 + 24) : 0;
    gPsfSyncSelfMetric = selfMetric;
    if (!gPsfSyncOff && !gPsfSyncExtraOff) {
        out[p++] = 0x05;
        airplayPsfPut16(out + p, 21);
        p += 2;
        out[p++] = 0;                                             /* flags */
        airplayPsfPut16(out + p, 0);                              /* id */
        p += 2;
        out[p++] = following ? (UInt8)(sync.distance + 1) : 0;   /* distance to master */
        out[p++] = 0;
        memcpy(out + p, following ? sync.master : self, 6);
        p += 6;
        airplayPsfPut32(out + p, following ? sync.masterMetric : selfMetric);
        p += 4;
        airplayPsfPut32(out + p, selfMetric);
        p += 4;
        out[p++] = 0;
        out[p++] = 0;
        gPsfSyncV1Added++;
    }

    /* TLV 0x12 channel sequence, value length 41 */
    out[p++] = 0x12;
    airplayPsfPut16(out + p, 41);
    p += 2;
    p += airplayPsfPutChanSeq(out + p);
    out[p++] = 0;
    out[p++] = 0;
    out[p++] = 0;

    /* IO80211's own TLVs */
    const size_t tplStart = p;
    memcpy(out + p, owner->syncFrameTemplate, tplLen);
    p += tplLen;

    /* PSFSYNC-20261016: election v2 follows the master we take timing from; sync tree TLV 0x14 */
    if (!gPsfSyncOff) {
        size_t l2 = 0;
        uint8_t *ov2 = (uint8_t *)airplayPsfFindTlv(out + tplStart, tplLen, 0x18, &l2);
        if (ov2 == nullptr || l2 < 28) {
            gPsfSyncV2Missing++;
        } else if (following) {
            memcpy(ov2 + 0, sync.master, 6);
            memcpy(ov2 + 6, sync.peer, 6);
            airplayPsfPut32(ov2 + 12, sync.masterCounter);
            airplayPsfPut32(ov2 + 16, sync.distance + 1);
            airplayPsfPut32(ov2 + 20, sync.masterMetric);
            gPsfSyncV2Patched++;
        }
        if (!gPsfSyncExtraOff &&
            airplayPsfFindTlv(owner->syncFrameTemplate, tplLen, 0x14, nullptr) == nullptr) {
            out[p++] = 0x14;
            airplayPsfPut16(out + p, following ? 12 : 6);
            p += 2;
            memcpy(out + p, self, 6);
            p += 6;
            if (following) {
                memset(out + p, 0, 6);
                p += 6;
            }
            gPsfSyncTreeAdded++;
        }
    }
    {
        const UInt64 nowUsP = nowNs / 1000ULL;
        if (gPsfSyncLastPublishUs == 0 || nowUsP - gPsfSyncLastPublishUs >= 1000000ULL) {
            gPsfSyncLastPublishUs = nowUsP;
#define PSFSYNC_PUB(n, v) owner->setProperty(n, (unsigned long long)(v), 32)
            PSFSYNC_PUB("AIRPLAYPsfSyncOn", gPsfSyncOff ? 0 : 1);
            PSFSYNC_PUB("AIRPLAYPsfEncLegacyOn", airplayPsfEncLegacyOn() ? 1 : 0); /* PSFENC */
            PSFSYNC_PUB("AIRPLAYPsfEncUnmapped", gPsfEncUnmapped);
            PSFSYNC_PUB("AIRPLAYPsfSyncExtraOn", (gPsfSyncOff || gPsfSyncExtraOff) ? 0 : 1);
            PSFSYNC_PUB("AIRPLAYPsfSyncFollowing", following ? 1 : 0);
            PSFSYNC_PUB("AIRPLAYPsfSyncRxParsed", gPsfSyncRxParsed);
            PSFSYNC_PUB("AIRPLAYPsfSyncRxBad", gPsfSyncRxBad);
            PSFSYNC_PUB("AIRPLAYPsfSyncRxSelfMaster", gPsfSyncRxSelfMaster);
            PSFSYNC_PUB("AIRPLAYPsfSyncRxIgnored", gPsfSyncRxIgnored);
            PSFSYNC_PUB("AIRPLAYPsfSyncSwitches", gPsfSyncSwitches);
            PSFSYNC_PUB("AIRPLAYPsfSyncResets", gPsfSyncResets);
            PSFSYNC_PUB("AIRPLAYPsfSyncAdjEarly", gPsfSyncAdjEarly);
            PSFSYNC_PUB("AIRPLAYPsfSyncAdjLate", gPsfSyncAdjLate);
            PSFSYNC_PUB("AIRPLAYPsfSyncLastErrUs", gPsfSyncLastErrUs);
            PSFSYNC_PUB("AIRPLAYPsfSyncTxFollowing", gPsfSyncTxFollowing);
            PSFSYNC_PUB("AIRPLAYPsfSyncTxOwnClock", gPsfSyncTxOwnClock);
            PSFSYNC_PUB("AIRPLAYPsfSyncV2Patched", gPsfSyncV2Patched);
            PSFSYNC_PUB("AIRPLAYPsfSyncV2Missing", gPsfSyncV2Missing);
            PSFSYNC_PUB("AIRPLAYPsfSyncV1Added", gPsfSyncV1Added);
            PSFSYNC_PUB("AIRPLAYPsfSyncTreeAdded", gPsfSyncTreeAdded);
            PSFSYNC_PUB("AIRPLAYPsfSyncLastTxc", gPsfSyncLastTxc);
            PSFSYNC_PUB("AIRPLAYPsfSyncLastAwSeq", gPsfSyncLastAwSeq);
            PSFSYNC_PUB("AIRPLAYPsfSyncLastPeerTxc", gPsfSyncLastPeerTxc);
            PSFSYNC_PUB("AIRPLAYPsfSyncLastPeerSeq", gPsfSyncLastPeerSeq);
            PSFSYNC_PUB("AIRPLAYPsfSyncMasterMetric", following ? sync.masterMetric : 0);
            PSFSYNC_PUB("AIRPLAYPsfSyncSelfMetric", gPsfSyncSelfMetric);
            PSFSYNC_PUB("AIRPLAYPsfSyncDistance", following ? sync.distance + 1 : 0);
#undef PSFSYNC_PUB
            if (following) {
                OSData *pd = OSData::withBytes(sync.peer, 6);
                if (pd != nullptr) {
                    owner->setProperty("AIRPLAYPsfSyncPeer", pd);
                    pd->release();
                }
                OSData *md = OSData::withBytes(sync.master, 6);
                if (md != nullptr) {
                    owner->setProperty("AIRPLAYPsfSyncMaster", md);
                    md->release();
                }
            }
        }
        { /* PSFENC: one fresh sample of the PSF as sent with the new encoding */
            static volatile UInt32 sEncSampled = 0;
            if (__sync_bool_compare_and_swap(&sEncSampled, 0, 1)) {
                OSData *es = OSData::withBytes(out, (unsigned int)(p < 384 ? p : 384));
                if (es != nullptr) {
                    owner->setProperty("AIRPLAYPsfTxSampleEnc", es);
                    es->release();
                }
            }
        }
        if (following && __sync_bool_compare_and_swap(&gPsfSyncSampled, 0, 1)) {
            OSData *ts = OSData::withBytes(out, (unsigned int)(p < 384 ? p : 384));
            if (ts != nullptr) {
                owner->setProperty("AIRPLAYPsfTxSampleSync", ts);
                ts->release();
            }
        }
    }

    if (__sync_bool_compare_and_swap(&gAirplayPsfTxSampled, 0, 1)) {
        OSData *tx = OSData::withBytes(out, (unsigned int)(p < 384 ? p : 384));
        if (tx != nullptr) {
            owner->setProperty("AIRPLAYPsfTxSample", tx);
            tx->release();
        }
        OSData *tpl = OSData::withBytes(owner->syncFrameTemplate,
                                        (unsigned int)(tplLen < 64 ? tplLen : 64));
        if (tpl != nullptr) {
            owner->setProperty("AIRPLAYPsfTemplateHead", tpl);
            tpl->release();
        }
        owner->setProperty("AIRPLAYPsfTemplateLen", (unsigned long long)tplLen, 32);
        owner->setProperty("AIRPLAYPsfTxSampleLen", (unsigned long long)p, 32);
    }
    return p;
}

static UInt32
airplayReadLE32(const UInt8 *p)
{
    return
        ((UInt32)p[0]) |
        ((UInt32)p[1] << 8) |
        ((UInt32)p[2] << 16) |
        ((UInt32)p[3] << 24);
}

static void
airplayCacheSonomaSchedule(
    IOService *service,
    const void *payload
)
{
    if (service == nullptr || payload == nullptr)
        return;

    const UInt8 *raw =
        reinterpret_cast<const UInt8 *>(payload);

    const UInt32 version =
        airplayReadLE32(raw + 0);

    const UInt8 length         = raw[5];
    const UInt8 encoding       = raw[6];
    const UInt8 stepCount      = raw[7];
    const UInt8 duplicateCount = raw[8];
    const UInt8 fillChannel    = raw[9];

    UInt8 valid =
        version == APPLE80211_VERSION &&
        length > 0 &&
        length <= 16;

    UInt8 channels8[16] = {};
    UInt32 flags32[16] = {};

    for (unsigned int i = 0; i < 16; i++) {

        UInt32 channel = 0;
        UInt32 flags = 0;

        if (i < length && i < 16) {

            const unsigned int off =
                12 + (i * 12);

            const UInt32 slotVersion =
                airplayReadLE32(raw + off + 0);

            channel =
                airplayReadLE32(raw + off + 4);

            flags =
                airplayReadLE32(raw + off + 8);

            if (slotVersion != APPLE80211_VERSION)
                valid = 0;
        }

        gAirplayAWDLScheduleCache.channels[i] =
            channel;

        gAirplayAWDLScheduleCache.flags[i] =
            flags;

        channels8[i] =
            (UInt8)(channel & 0xff);

        flags32[i] =
            flags;
    }

    gAirplayAWDLScheduleCache.version =
        version;

    gAirplayAWDLScheduleCache.length =
        length;

    gAirplayAWDLScheduleCache.encoding =
        encoding;

    gAirplayAWDLScheduleCache.stepCount =
        stepCount;

    gAirplayAWDLScheduleCache.duplicateCount =
        duplicateCount;

    gAirplayAWDLScheduleCache.fillChannel =
        fillChannel;

    gAirplayAWDLScheduleCache.valid =
        valid;

    gAirplayAWDLScheduleCache.generation++;

    service->setProperty(
        "AIRPLAYScheduleCacheGeneration",
        (unsigned long long)
            gAirplayAWDLScheduleCache.generation,
        32
    );

    service->setProperty(
        "AIRPLAYScheduleCacheValid",
        (unsigned long long)valid,
        8
    );

    service->setProperty(
        "AIRPLAYScheduleVersion",
        (unsigned long long)version,
        32
    );

    service->setProperty(
        "AIRPLAYScheduleLength",
        (unsigned long long)length,
        8
    );

    service->setProperty(
        "AIRPLAYScheduleEncoding",
        (unsigned long long)encoding,
        8
    );

    service->setProperty(
        "AIRPLAYScheduleStepCount",
        (unsigned long long)stepCount,
        8
    );

    service->setProperty(
        "AIRPLAYScheduleDuplicateCount",
        (unsigned long long)duplicateCount,
        8
    );

    service->setProperty(
        "AIRPLAYScheduleFillChannel",
        (unsigned long long)fillChannel,
        8
    );

    OSData *channelData =
        OSData::withBytes(
            channels8,
            sizeof(channels8)
        );

    if (channelData != nullptr) {
        service->setProperty(
            "AIRPLAYScheduleChannels16",
            channelData
        );
        channelData->release();
    }

    OSData *flagData =
        OSData::withBytes(
            flags32,
            sizeof(flags32)
        );

    if (flagData != nullptr) {
        service->setProperty(
            "AIRPLAYScheduleFlags16",
            flagData
        );
        flagData->release();
    }

    service->setProperty(
        "AIRPLAYScheduleReady",
        (unsigned long long)(
            gAirplayAWDLScheduleCache.valid &&
            gAirplayAWDLScheduleCache.armed
                ? 1 : 0
        ),
        8
    );
}

extern "C" bool airplayAwdlExperimentsEnabled(void); /* SCHEDARM */
extern "C" void airplayAwdlSetSyncActive(bool on); /* P2PGATE */

static void
airplayLifeProperty(IOService *service, const char *key, UInt8 value)
{
    OSData *data = OSData::withBytes(&value, sizeof(value));

    if (data != nullptr) {
        service->setProperty(key, data);
        data->release();
    }
}


// Bounded queue diagnostics: static storage preserves the interface ABI.
// Counts are callback arguments, not proof of packets transmitted/received.
struct AirplayQueueProbe {
    volatile UInt32 calls;
    volatile UInt32 sampledCountTotal;
};

static void
airplayQueueProbeRecord(
    OSObject *target, AirplayQueueProbe *probe, UInt32 count,
    const char *callsKey, const char *lastKey, const char *totalKey)
{
    UInt32 call = __sync_add_and_fetch(&probe->calls, 1);
    if (call > 32)
        return;
    UInt32 total = __sync_add_and_fetch(&probe->sampledCountTotal, count);
    IOService *service = OSDynamicCast(IOService, target);
    if (service == nullptr)
        return;
    service->setProperty(callsKey, (unsigned long long)call, 32);
    service->setProperty(lastKey, (unsigned long long)count, 32);
    service->setProperty(totalKey, (unsigned long long)total, 32);
}


/*
 * AWDL exact-mbuf identity tracer.
 * Diagnostic only: does not alter packet data or routing.
 */
static mbuf_t gAirplayAWDLTraceSlots[128] = {};
static UInt32 gAirplayAWDLTraceTagsAdded = 0;
static UInt32 gAirplayAWDLTraceSlotsFull = 0;

extern "C" bool
airplayAWDLTraceTrackMbuf(mbuf_t m)
{
    if (m == nullptr)
        return false;

    const unsigned count =
        sizeof(gAirplayAWDLTraceSlots) /
        sizeof(gAirplayAWDLTraceSlots[0]);

    for (unsigned n = 0; n < count; ++n) {
        mbuf_t expected = nullptr;

        if (__atomic_compare_exchange_n(
                &gAirplayAWDLTraceSlots[n],
                &expected,
                m,
                false,
                __ATOMIC_ACQ_REL,
                __ATOMIC_ACQUIRE)) {

            __atomic_add_fetch(
                &gAirplayAWDLTraceTagsAdded,
                (UInt32)1,
                __ATOMIC_RELAXED
            );

            return true;
        }
    }

    __atomic_add_fetch(
        &gAirplayAWDLTraceSlotsFull,
        (UInt32)1,
        __ATOMIC_RELAXED
    );

    return false;
}

extern "C" bool
airplayAWDLTraceTakeMbuf(mbuf_t m)
{
    if (m == nullptr)
        return false;

    const unsigned count =
        sizeof(gAirplayAWDLTraceSlots) /
        sizeof(gAirplayAWDLTraceSlots[0]);

    for (unsigned n = 0; n < count; ++n) {
        mbuf_t current =
            __atomic_load_n(
                &gAirplayAWDLTraceSlots[n],
                __ATOMIC_ACQUIRE
            );

        if (current != m)
            continue;

        mbuf_t expected = m;

        if (__atomic_compare_exchange_n(
                &gAirplayAWDLTraceSlots[n],
                &expected,
                nullptr,
                false,
                __ATOMIC_ACQ_REL,
                __ATOMIC_ACQUIRE)) {
            return true;
        }
    }

    return false;
}

extern "C" bool
airplayAWDLTraceUntrackMbuf(mbuf_t m)
{
    if (m == nullptr)
        return false;

    const unsigned count =
        sizeof(gAirplayAWDLTraceSlots) /
        sizeof(gAirplayAWDLTraceSlots[0]);

    for (unsigned n = 0; n < count; ++n) {
        mbuf_t current =
            __atomic_load_n(
                &gAirplayAWDLTraceSlots[n],
                __ATOMIC_ACQUIRE
            );

        if (current != m)
            continue;

        mbuf_t expected = m;

        return __atomic_compare_exchange_n(
            &gAirplayAWDLTraceSlots[n],
            &expected,
            nullptr,
            false,
            __ATOMIC_ACQ_REL,
            __ATOMIC_ACQUIRE
        );
    }

    return false;
}



/*
 * Sonoma AWDL TX completion-context map.
 *
 * Keep this independent of the proven exact-mbuf tracer.
 *
 * The original IOSkywalkPacket remains the completion identity while the
 * copied mbuf travels through AirportItlwm's normal Intel TX path.
 *
 * Only the first 16 packets per boot are retained for this experiment.
 */
static mbuf_t gAirplayAWDLCompletionMbufSlots[32] = {};
static void *gAirplayAWDLCompletionPacketSlots[32] = {};

static volatile UInt32 gAirplayAWDLCompletionMapLock = 0;

static UInt32 gAirplayAWDLCompletionMapTracked = 0;
static UInt32 gAirplayAWDLCompletionMapFull = 0;
static UInt32 gAirplayAWDLCompletionMapBudgetSkipped = 0;   /* AWTXDONE: budget removed, stays 0 */
static UInt32 gAirplayAWDLCompletionImmediate = 0;          /* AWTXDONE: returned at once (map full) */
extern "C" IOReturn airplayAWDLCompletionEnqueue(void *packetContext);

static void
airplayAWDLCompletionMapLock(void)
{
    while (__sync_lock_test_and_set(
        &gAirplayAWDLCompletionMapLock,
        (UInt32)1) != 0) {
    }
}

static void
airplayAWDLCompletionMapUnlock(void)
{
    __sync_lock_release(
        &gAirplayAWDLCompletionMapLock
    );
}

extern "C" bool
airplayAWDLCompletionTrackMbuf(
    mbuf_t m,
    void *packetContext)
{
    if (m == nullptr || packetContext == nullptr)
        return false;

    airplayAWDLCompletionMapLock();

    /* AWTXDONE-20261015: the old 16-per-boot budget leaked every later packet (pool of 64 ->
     * awdl0 dead after 79 sends). Slots are freed at dequeue, so no budget is needed. */

    const unsigned count =
        sizeof(gAirplayAWDLCompletionMbufSlots) /
        sizeof(gAirplayAWDLCompletionMbufSlots[0]);

    for (unsigned n = 0; n < count; ++n) {
        if (gAirplayAWDLCompletionMbufSlots[n] != nullptr)
            continue;

        gAirplayAWDLCompletionPacketSlots[n] =
            packetContext;

        gAirplayAWDLCompletionMbufSlots[n] =
            m;

        gAirplayAWDLCompletionMapTracked++;

        airplayAWDLCompletionMapUnlock();
        return true;
    }

    gAirplayAWDLCompletionMapFull++;

    airplayAWDLCompletionMapUnlock();
    return false;
}

extern "C" void *
airplayAWDLCompletionTakeMbuf(mbuf_t m)
{
    if (m == nullptr)
        return nullptr;

    airplayAWDLCompletionMapLock();

    const unsigned count =
        sizeof(gAirplayAWDLCompletionMbufSlots) /
        sizeof(gAirplayAWDLCompletionMbufSlots[0]);

    for (unsigned n = 0; n < count; ++n) {
        if (gAirplayAWDLCompletionMbufSlots[n] != m)
            continue;

        void *packetContext =
            gAirplayAWDLCompletionPacketSlots[n];

        gAirplayAWDLCompletionPacketSlots[n] =
            nullptr;

        gAirplayAWDLCompletionMbufSlots[n] =
            nullptr;

        airplayAWDLCompletionMapUnlock();
        return packetContext;
    }

    airplayAWDLCompletionMapUnlock();
    return nullptr;
}

extern "C" bool
airplayAWDLCompletionUntrackMbuf(mbuf_t m)
{
    if (m == nullptr)
        return false;

    airplayAWDLCompletionMapLock();

    const unsigned count =
        sizeof(gAirplayAWDLCompletionMbufSlots) /
        sizeof(gAirplayAWDLCompletionMbufSlots[0]);

    for (unsigned n = 0; n < count; ++n) {
        if (gAirplayAWDLCompletionMbufSlots[n] != m)
            continue;

        gAirplayAWDLCompletionPacketSlots[n] =
            nullptr;

        gAirplayAWDLCompletionMbufSlots[n] =
            nullptr;

        airplayAWDLCompletionMapUnlock();
        return true;
    }

    airplayAWDLCompletionMapUnlock();
    return false;
}


static UInt32
airplayAWDLTxSubmission(
    OSObject *target,
    IOSkywalkTxSubmissionQueue *queue,
    IOSkywalkPacket * const *packets,
    UInt32 count,
    void *)
{
    static UInt32 bridgeCalls = 0;
    static UInt32 packetsSeen = 0;
    static UInt32 mbufsBuilt = 0;
    static UInt32 intelAccepted = 0;
    static UInt32 failures = 0;

    bridgeCalls++;

    AirportItlwmAWDLInterface *awdl =
        OSDynamicCast(AirportItlwmAWDLInterface, target);

    if (awdl != nullptr) {
        awdl->setProperty(
            "AIRPLAYTXBridgeCalls",
            (unsigned long long)bridgeCalls,
            32
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeLastCount",
            (unsigned long long)count,
            32
        );
    }

    if (awdl == nullptr ||
        packets == nullptr ||
        count == 0) {
        return 0;
    }

    AirportItlwm *owner =
        OSDynamicCast(AirportItlwm, awdl->getProvider());

    awdl->setProperty(
        "AIRPLAYTXBridgeOwnerFound",
        (unsigned long long)(owner != nullptr ? 1 : 0),
        8
    );

    if (owner == nullptr)
        return 0;

    UInt32 consumed = 0;

    /*
     * TX bridge stage probe.
     *
     * FailureStage:
     *   0 = no failure recorded for current packet
     *   1 = packet pointer null
     *   2 = invalid packet length
     *   3 = no memory descriptor
     *   4 = descriptor bounds failure
     *   5 = IOMalloc failure
     *   6 = short readBytes()
     *   7 = mbuf_allocpacket failure
     *   8 = mbuf_copyback failure
     *   9 = Intel outputPacket rejected
     *
     * LastStage:
     *   1 = packet pointer valid
     *   2 = metadata obtained
     *   3 = memory descriptor valid
     *   4 = descriptor bounds valid
     *   5 = temporary buffer allocated
     *   6 = descriptor bytes copied
     *   7 = mbuf allocated
     *   8 = mbuf copyback succeeded
     *   9 = mbuf ready
     *  10 = Intel outputPacket called
     *  11 = Intel accepted packet
     */
    for (UInt32 i = 0; i < count; i++) {

        awdl->setProperty(
            "AIRPLAYTXBridgePacketIndex",
            (unsigned long long)i,
            32
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeFailureStage",
            (unsigned long long)0,
            32
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeLastStage",
            (unsigned long long)0,
            32
        );

        IOSkywalkPacket *packet = packets[i];

        if (packet == nullptr) {
            awdl->setProperty(
                "AIRPLAYTXBridgeFailureStage",
                (unsigned long long)1,
                32
            );
            failures++;
            break;
        }

        awdl->setProperty(
            "AIRPLAYTXBridgeLastStage",
            (unsigned long long)1,
            32
        );

        packetsSeen++;

        UInt32 length = packet->getDataLength();
        UInt16 offset = packet->getDataOffset();

        awdl->setProperty(
            "AIRPLAYTXBridgeLastLength",
            (unsigned long long)length,
            32
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeLastOffset",
            (unsigned long long)offset,
            16
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeLastStage",
            (unsigned long long)2,
            32
        );

        if (length == 0 || length > 4096) {
            awdl->setProperty(
                "AIRPLAYTXBridgeFailureStage",
                (unsigned long long)2,
                32
            );
            failures++;
            break;
        }

        /*
         * Sonoma Skywalk TX packets do not expose their backing storage
         * through IOSkywalkPacket::getMemoryDescriptor().
         *
         * Walk the packet -> packet buffer -> memory segment path instead.
         * Keep using IOMemoryDescriptor::readBytes() once we have the
         * descriptor owned by the memory segment.
         */

        awdl->setProperty(
            "AIRPLAYTXBridgeMemoryPresent",
            (unsigned long long)0,
            8
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeMemoryLength",
            (unsigned long long)0,
            64
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeBoundsOK",
            (unsigned long long)0,
            8
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeCopiedBytes",
            (unsigned long long)0,
            64
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeMbufAllocErr",
            (unsigned long long)0,
            32
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeCopybackErr",
            (unsigned long long)0,
            32
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeBufferCount",
            (unsigned long long)0,
            32
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeBuffersReturned",
            (unsigned long long)0,
            32
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeBufferPresent",
            (unsigned long long)0,
            8
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeBufferLength",
            (unsigned long long)0,
            32
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeBufferDataOffset",
            (unsigned long long)0,
            32
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeSegmentPresent",
            (unsigned long long)0,
            8
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeSegmentOffset",
            (unsigned long long)0,
            64
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeSourceOffset",
            (unsigned long long)0,
            64
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeBufferPathStage",
            (unsigned long long)0,
            32
        );

        UInt32 bufferCount =
            packet->getPacketBufferCount();

        awdl->setProperty(
            "AIRPLAYTXBridgeBufferCount",
            (unsigned long long)bufferCount,
            32
        );

        IOSkywalkPacketBuffer *buffer = nullptr;

        UInt32 buffersReturned =
            packet->getPacketBuffers(
                &buffer,
                1
            );

        awdl->setProperty(
            "AIRPLAYTXBridgeBuffersReturned",
            (unsigned long long)buffersReturned,
            32
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeBufferPresent",
            (unsigned long long)(buffer != nullptr ? 1 : 0),
            8
        );

        if (bufferCount == 0 ||
            buffersReturned != 1 ||
            buffer == nullptr) {

            awdl->setProperty(
                "AIRPLAYTXBridgeFailureStage",
                (unsigned long long)3,
                32
            );

            failures++;
            break;
        }

        awdl->setProperty(
            "AIRPLAYTXBridgeBufferPathStage",
            (unsigned long long)1,
            32
        );

        /*
         * These are public fields in the bundled Sonoma Skywalk headers.
         * Reading them directly avoids introducing additional non-virtual
         * Skywalk accessor symbols into the kext.
         */
        UInt32 bufferLength =
            buffer->mDataLength;

        UInt16 bufferDataOffset =
            buffer->mDataOffset;

        IOSkywalkMemorySegment *segment =
            buffer->mMemorySegment;

        UInt64 segmentOffset =
            buffer->mMemorySegmentOffset;

        awdl->setProperty(
            "AIRPLAYTXBridgeBufferLength",
            (unsigned long long)bufferLength,
            32
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeBufferDataOffset",
            (unsigned long long)bufferDataOffset,
            32
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeSegmentPresent",
            (unsigned long long)(segment != nullptr ? 1 : 0),
            8
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeSegmentOffset",
            (unsigned long long)segmentOffset,
            64
        );

        if (bufferLength < length ||
            segment == nullptr) {

            awdl->setProperty(
                "AIRPLAYTXBridgeFailureStage",
                (unsigned long long)3,
                32
            );

            failures++;
            break;
        }

        awdl->setProperty(
            "AIRPLAYTXBridgeBufferPathStage",
            (unsigned long long)2,
            32
        );

        /*
         * IOSkywalkMemorySegment layout in our Sonoma SDK:
         *
         *   +32  IOMemoryDescriptor *mMemoryDescriptor
         *
         * Read that field directly so we don't add another potentially
         * unavailable Skywalk accessor symbol at load time.
         */
        IOMemoryDescriptor *memory = nullptr;

        memcpy(
            &memory,
            reinterpret_cast<unsigned char *>(segment) + 32,
            sizeof(memory)
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeMemoryPresent",
            (unsigned long long)(memory != nullptr ? 1 : 0),
            8
        );

        if (memory == nullptr) {

            awdl->setProperty(
                "AIRPLAYTXBridgeFailureStage",
                (unsigned long long)3,
                32
            );

            failures++;
            break;
        }

        awdl->setProperty(
            "AIRPLAYTXBridgeBufferPathStage",
            (unsigned long long)3,
            32
        );

        IOByteCount memoryLength =
            memory->getLength();

        awdl->setProperty(
            "AIRPLAYTXBridgeMemoryLength",
            (unsigned long long)memoryLength,
            64
        );

        if (segmentOffset >
                (~0ULL - (UInt64)bufferDataOffset)) {

            awdl->setProperty(
                "AIRPLAYTXBridgeFailureStage",
                (unsigned long long)4,
                32
            );

            failures++;
            break;
        }

        UInt64 sourceOffset =
            segmentOffset +
            (UInt64)bufferDataOffset;

        awdl->setProperty(
            "AIRPLAYTXBridgeSourceOffset",
            (unsigned long long)sourceOffset,
            64
        );

        if (sourceOffset > (UInt64)memoryLength ||
            (UInt64)length >
                ((UInt64)memoryLength - sourceOffset)) {

            awdl->setProperty(
                "AIRPLAYTXBridgeFailureStage",
                (unsigned long long)4,
                32
            );

            failures++;
            break;
        }

        awdl->setProperty(
            "AIRPLAYTXBridgeBoundsOK",
            (unsigned long long)1,
            8
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeBufferPathStage",
            (unsigned long long)4,
            32
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeLastStage",
            (unsigned long long)4,
            32
        );

        void *bytes =
            IOMalloc(length);

        if (bytes == nullptr) {

            awdl->setProperty(
                "AIRPLAYTXBridgeFailureStage",
                (unsigned long long)5,
                32
            );

            failures++;
            break;
        }

        awdl->setProperty(
            "AIRPLAYTXBridgeLastStage",
            (unsigned long long)5,
            32
        );

        IOByteCount copied =
            memory->readBytes(
                sourceOffset,
                bytes,
                length
            );

        awdl->setProperty(
            "AIRPLAYTXBridgeCopiedBytes",
            (unsigned long long)copied,
            64
        );

        if (copied != length) {

            IOFree(bytes, length);

            awdl->setProperty(
                "AIRPLAYTXBridgeFailureStage",
                (unsigned long long)6,
                32
            );

            failures++;
            break;
        }

        awdl->setProperty(
            "AIRPLAYTXBridgeBufferPathStage",
            (unsigned long long)5,
            32
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeLastStage",
            (unsigned long long)6,
            32
        );

        mbuf_t m = nullptr;

        errno_t err =
            mbuf_allocpacket(
                MBUF_DONTWAIT,
                length,
                nullptr,
                &m
            );

        awdl->setProperty(
            "AIRPLAYTXBridgeMbufAllocErr",
            (unsigned long long)(UInt32)err,
            32
        );

        if (err != 0 || m == nullptr) {
            IOFree(bytes, length);

            awdl->setProperty(
                "AIRPLAYTXBridgeFailureStage",
                (unsigned long long)7,
                32
            );

            failures++;
            break;
        }

        awdl->setProperty(
            "AIRPLAYTXBridgeLastStage",
            (unsigned long long)7,
            32
        );

        err =
            mbuf_copyback(
                m,
                0,
                length,
                bytes,
                MBUF_DONTWAIT
            );

        awdl->setProperty(
            "AIRPLAYTXBridgeCopybackErr",
            (unsigned long long)(UInt32)err,
            32
        );

        IOFree(bytes, length);

        if (err != 0) {
            mbuf_freem(m);

            awdl->setProperty(
                "AIRPLAYTXBridgeFailureStage",
                (unsigned long long)8,
                32
            );

            failures++;
            break;
        }

        awdl->setProperty(
            "AIRPLAYTXBridgeLastStage",
            (unsigned long long)8,
            32
        );

        mbuf_pkthdr_setlen(m, length);

        mbufsBuilt++;

        bool airplayTraceTagged =
            airplayAWDLTraceTrackMbuf(m);

        bool airplayCompletionTracked =
            airplayAWDLCompletionTrackMbuf(
                m,
                (void *)packet
            );

        awdl->setProperty(
            "AIRPLAYTXCompletionMapTracked",
            (unsigned long long)gAirplayAWDLCompletionMapTracked,
            32
        );

        awdl->setProperty(
            "AIRPLAYTXCompletionMapFull",
            (unsigned long long)gAirplayAWDLCompletionMapFull,
            32
        );

        awdl->setProperty(
            "AIRPLAYTXCompletionMapBudgetSkipped",
            (unsigned long long)gAirplayAWDLCompletionMapBudgetSkipped,
            32
        );

        awdl->setProperty(
            "AIRPLAYTXCompletionLastTrackResult",
            (unsigned long long)(airplayCompletionTracked ? 1 : 0),
            8
        );

        awdl->setProperty(
            "AIRPLAYTXTraceTagsAdded",
            (unsigned long long)__atomic_load_n(
                &gAirplayAWDLTraceTagsAdded,
                __ATOMIC_RELAXED
            ),
            32
        );

        awdl->setProperty(
            "AIRPLAYTXTraceSlotsFull",
            (unsigned long long)__atomic_load_n(
                &gAirplayAWDLTraceSlotsFull,
                __ATOMIC_RELAXED
            ),
            32
        );

        awdl->setProperty(
            "AIRPLAYTXTraceLastTagResult",
            (unsigned long long)(airplayTraceTagged ? 1 : 0),
            8
        );


        awdl->setProperty(
            "AIRPLAYTXBridgeLastStage",
            (unsigned long long)9,
            32
        );

        UInt32 result =
            owner->outputPacket(
                m,
                nullptr
            );

        awdl->setProperty(
            "AIRPLAYTXBridgeLastIntelResult",
            (unsigned long long)result,
            32
        );

        awdl->setProperty(
            "AIRPLAYTXBridgeLastStage",
            (unsigned long long)10,
            32
        );

        /*
         * outputPacket() owns the mbuf once called.
         * Do not free it here.
         */
        if (result != kIOReturnOutputSuccess) {

            if (airplayTraceTagged)
                airplayAWDLTraceUntrackMbuf(m);

            if (airplayCompletionTracked)
                airplayAWDLCompletionUntrackMbuf(m);


            awdl->setProperty(
                "AIRPLAYTXBridgeFailureStage",
                (unsigned long long)9,
                32
            );

            failures++;
            break;
        }

        intelAccepted++;
        consumed++;

        if (!airplayCompletionTracked) {
            /* AWTXDONE: not tracked (map full) - data already copied, hand the packet back now */
            airplayAWDLCompletionEnqueue((void *)packet);
            gAirplayAWDLCompletionImmediate++;
            awdl->setProperty("AIRPLAYTXCompletionImmediate",
                              (unsigned long long)gAirplayAWDLCompletionImmediate, 32);
        }

        awdl->setProperty(
            "AIRPLAYTXBridgeLastStage",
            (unsigned long long)11,
            32
        );
    }

    awdl->setProperty(
        "AIRPLAYTXBridgePacketsSeen",
        (unsigned long long)packetsSeen,
        32
    );

    awdl->setProperty(
        "AIRPLAYTXBridgeMbufsBuilt",
        (unsigned long long)mbufsBuilt,
        32
    );

    awdl->setProperty(
        "AIRPLAYTXBridgeIntelAccepted",
        (unsigned long long)intelAccepted,
        32
    );

    awdl->setProperty(
        "AIRPLAYTXBridgeFailures",
        (unsigned long long)failures,
        32
    );

    awdl->setProperty(
        "AIRPLAYTXBridgeConsumed",
        (unsigned long long)consumed,
        32
    );

    return consumed;
}


static UInt32
airplayAWDLTxCompletion(
    OSObject *target,
    IOSkywalkTxCompletionQueue *,
    IOSkywalkPacket **,
    UInt32 count,
    void *)
{
    static AirplayQueueProbe queueProbe = {};
    airplayQueueProbeRecord(target, &queueProbe, count,
        "AIRPLAYQueueTxCompletionCallsSampled",
        "AIRPLAYQueueTxCompletionLastCountArg",
        "AIRPLAYQueueTxCompletionCountArgTotalSampled");
    static UInt32 probeHits = 0;
    if (probeHits < 20) {
        IOLog("AIRPLAY AWDL QUEUE: airplayAWDLTxCompletion hit=%u\n", probeHits + 1);
    }
    probeHits++;
    return 0;
}


static UInt32
airplayAWDLRxSubmission(
    OSObject *target,
    IOSkywalkRxSubmissionQueue *,
    IOSkywalkPacket * const *,
    UInt32 count,
    void *)
{
    static AirplayQueueProbe queueProbe = {};
    airplayQueueProbeRecord(target, &queueProbe, count,
        "AIRPLAYQueueRxSubmissionCallsSampled",
        "AIRPLAYQueueRxSubmissionLastCountArg",
        "AIRPLAYQueueRxSubmissionCountArgTotalSampled");
    static UInt32 probeHits = 0;
    if (probeHits < 20) {
        IOLog("AIRPLAY AWDL QUEUE: airplayAWDLRxSubmission hit=%u\n", probeHits + 1);
    }
    probeHits++;
    return 0;
}


static UInt32
airplayAWDLRxCompletion(
    OSObject *target,
    IOSkywalkRxCompletionQueue *,
    IOSkywalkPacket **,
    UInt32 count,
    void *)
{
    static AirplayQueueProbe queueProbe = {};
    airplayQueueProbeRecord(target, &queueProbe, count,
        "AIRPLAYQueueRxCompletionCallsSampled",
        "AIRPLAYQueueRxCompletionLastCountArg",
        "AIRPLAYQueueRxCompletionCountArgTotalSampled");
    static UInt32 probeHits = 0;
    if (probeHits < 20) {
        IOLog("AIRPLAY AWDL QUEUE: airplayAWDLRxCompletion hit=%u\n", probeHits + 1);
    }
    probeHits++;
    return 0;
}



/*
 * Sonoma V2 native AWDL resource bridge.
 *
 * airplayRegisterNativeAWDL() already creates these real Skywalk
 * resources.  Keep references to the successful registration's
 * objects so the V2 virtual getters can expose the same resources
 * back to IO80211 instead of returning inherited NULL/zero state.
 *
 * No AirportItlwmAWDLInterface fields are added: preserve the
 * physical 0x120 ABI size.
 */
static IOSkywalkPacketBufferPool *gAirplayAWDLNativePool = nullptr;
static IOSkywalkTxSubmissionQueue *gAirplayAWDLNativeTxSubmission = nullptr;
static IOSkywalkTxCompletionQueue *gAirplayAWDLNativeTxCompletion = nullptr;

/*
 * Called only after the exact copied mbuf reaches iwx_tx() and iwx_tx()
 * returns success.
 *
 * enqueuePackets() is virtual.  Do not add completePackets() here: that
 * non-virtual method introduced an unresolved symbol in the rejected build.
 */
static volatile UInt32 gAirplayAWDLCompletionBranchProbeCalls = 0;
static volatile UInt32 gTXComp16Outcomes = 0;
static volatile UInt32 gTXComp16NoContext = 0;
static volatile UInt32 gTXComp16NoQueue = 0;

extern "C" void
airplayTXComp16Snapshot(UInt32 *out, UInt32 *ctx,
                        UInt32 *queue, UInt32 *calls)
{
    *out = gTXComp16Outcomes;
    *ctx = gTXComp16NoContext;
    *queue = gTXComp16NoQueue;
    *calls = gAirplayAWDLCompletionBranchProbeCalls;
}


extern "C" IOReturn
airplayAWDLCompletionEnqueue(void *packetContext)
{
    const UInt32 callNo = __sync_add_and_fetch(
        &gAirplayAWDLCompletionBranchProbeCalls, (UInt32)1);

    if (packetContext == nullptr ||
        gAirplayAWDLNativeTxCompletion == nullptr) {
        if (callNo <= 16) {
            const UInt32 bit = 1U << (callNo - 1);
            if (packetContext == nullptr)
                __sync_fetch_and_or(&gTXComp16NoContext, bit);
            if (gAirplayAWDLNativeTxCompletion == nullptr)
                __sync_fetch_and_or(&gTXComp16NoQueue, bit);
        }
        return kIOReturnNotReady;
    }

    IOSkywalkPacket *packet =
        static_cast<IOSkywalkPacket *>(packetContext);

    const IOSkywalkPacket *packets[1] = {
        packet
    };

    IOReturn result =
        gAirplayAWDLNativeTxCompletion->enqueuePackets(
            packets,
            1,
            0
        );

    if (callNo <= 16) {
        const UInt32 outcome =
            result == kIOReturnSuccess ? 1U :
            result == kIOReturnNotReady ? 2U : 3U;

        __sync_fetch_and_or(
            &gTXComp16Outcomes,
            outcome << (2U * (callNo - 1))
        );
    }

    return result;
}

static IOSkywalkRxSubmissionQueue *gAirplayAWDLNativeRxSubmission = nullptr;
static IOSkywalkRxCompletionQueue *gAirplayAWDLNativeRxCompletion = nullptr;

/* AWRXDELIVER-20261016 / AWRXDELIVER2: AWDL data -> awdl0 via the registered Skywalk RX completion queue. */
static volatile UInt32 gRxDlv[40] = {};   /* AWRXDELIVER4: 33 slots used */
enum {
    kRxDlvCalls = 0, kRxDlvOk, kRxDlvAllocFail, kRxDlvBufFail, kRxDlvWriteFail, kRxDlvEnqFail,
    kRxDlvLastEnq, kRxDlvNoQueue, kRxDlvTooBig, kRxDlvStopped, kRxDlvConsecAlloc, kRxDlvMcast,
    kRxDlvUcast, kRxDlvLastEtherType, kRxDlvLastLen, kRxDlvOff,
    kRxDlvPrepRes, kRxDlvStateAlloc, kRxDlvStatePrep, kRxDlvSnapBufCount, kRxDlvSnapFlags,
    kRxDlvSnapMdLen, kRxDlvSnapSegOff, kRxDlvViaPktMd, kRxDlvPrepFail, kRxDlvBufFailSeg,
    kRxDlvBufFailLen, kRxDlvSnapTaken,
    kRxDlvQNoRing, kRxDlvQOffline28, kRxDlvQOfflineCC, kRxDlvQBusy, kRxDlvQReady, kRxDlvCount
};

/* INPUTFEED-20261017: feed received AWDL frames through IO80211's peer-input path. DEFAULT OFF. */
static AirportItlwmAWDLInterface *gAirplayAWDLIface = nullptr;
static int gInputFeedOn = -1;   /* -1 unknown, 0 off, 1 on (boot-arg -awdlinputfeed) */
static volatile UInt32 gFeed[8] = {};
enum { kFeedOn = 0, kFeedCalls, kFeedConsumed, kFeedNotConsumed, kFeedLastRet, kFeedIfaceNull, kFeedN };
extern "C" void
airplayRxDeliverSnapshot(UInt32 *out, UInt32 n)
{
    for (UInt32 i = 0; i < n && i < kRxDlvCount; i++)
        out[i] = gRxDlv[i];
}
/* AWRXDELIVER3: SDK IOSkywalkPacket vtable is 5 slots short after setDataOffsetAndLength (0x158).
 * Call prepare/complete through the real IOSkywalkFamily 14.8.7 slots. */
typedef IOReturn (*AirplayPktQueueFn)(IOSkywalkPacket *, IOSkywalkPacketQueue *, UInt32, UInt32);
static inline IOReturn
airplayPktPrepareWithQueue(IOSkywalkPacket *pkt, IOSkywalkPacketQueue *q, UInt32 dir)
{
    void **vt = *reinterpret_cast<void ***>(pkt);
    return reinterpret_cast<AirplayPktQueueFn>(vt[0x188 / 8])(pkt, q, dir, 0);
}
static inline IOReturn
airplayPktCompleteWithQueue(IOSkywalkPacket *pkt, IOSkywalkPacketQueue *q, UInt32 dir)
{
    void **vt = *reinterpret_cast<void ***>(pkt);
    return reinterpret_cast<AirplayPktQueueFn>(vt[0x198 / 8])(pkt, q, dir, 0);
}
static inline UInt32
airplayPktState(IOSkywalkPacket *pkt)
{
    UInt32 st = 0;
    memcpy(&st, reinterpret_cast<unsigned char *>(pkt) + 88, sizeof(st));   /* mPacketState */
    return st;
}
static void
airplayRxDlvSnap(IOSkywalkPacket *pkt, IOSkywalkPacketBuffer *buf, UInt32 bufCount,
                 IOMemoryDescriptor *segMd, UInt64 segOff)
{
    if (gRxDlv[kRxDlvSnapTaken])
        return;
    gRxDlv[kRxDlvSnapTaken] = 1;
    IOMemoryDescriptor *pmd = pkt ? pkt->getMemoryDescriptor() : nullptr;
    UInt32 f = 0;
    if (buf) f |= 1;
    if (buf && buf->mMemorySegment) f |= 2;
    if (segMd) f |= 4;
    if (pmd) f |= 8;
    gRxDlv[kRxDlvSnapFlags] = f;
    gRxDlv[kRxDlvSnapBufCount] = bufCount;
    gRxDlv[kRxDlvSnapMdLen] = (UInt32)(segMd ? segMd->getLength() : (pmd ? pmd->getLength() : 0));
    gRxDlv[kRxDlvSnapSegOff] = (UInt32)segOff;
}
extern "C" int
AirportItlwmAWDLDataRx(const uint8_t *dst, const uint8_t *src, const uint8_t *etherType,
                       const uint8_t *payload, size_t payloadLen)
{
    static int off = -1;
    if (off < 0) {
        int v = 0;
        off = PE_parse_boot_argn("-awdlrxdeliveroff", &v, sizeof(v)) ? 1 : 0;
        gRxDlv[kRxDlvOff] = (UInt32)off;
    }
    gRxDlv[kRxDlvCalls]++;
    if (off || gRxDlv[kRxDlvStopped])
        return 1;
    IOSkywalkPacketBufferPool *pool = gAirplayAWDLNativePool;
    IOSkywalkRxCompletionQueue *rxc = gAirplayAWDLNativeRxCompletion;
    if (pool == nullptr || rxc == nullptr) {
        gRxDlv[kRxDlvNoQueue]++;
        return 2;
    }
    const size_t total = 14 + payloadLen;
    if (payloadLen == 0 || total > 2048) {
        gRxDlv[kRxDlvTooBig]++;
        return 3;
    }
    {   /* AWRXDELIVER4: same conditions IOSkywalkRxCompletionQueue::enqueuePackets checks (14.8.7) */
        const unsigned char *q = reinterpret_cast<const unsigned char *>(rxc);
        void *ring = nullptr;
        memcpy(&ring, q + 0x30, sizeof(ring));
        const bool on28 = q[0x28] != 0, oncc = q[0xcc] != 0, busy = (q[0x118] & 1) != 0;
        gRxDlv[kRxDlvQReady] = (ring && on28 && oncc && !busy) ? 1 : 0;
        if (ring == nullptr) { gRxDlv[kRxDlvQNoRing]++; return 10; }
        if (!on28) { gRxDlv[kRxDlvQOffline28]++; return 11; }
        if (!oncc) { gRxDlv[kRxDlvQOfflineCC]++; return 12; }
        if (busy) { gRxDlv[kRxDlvQBusy]++; return 13; }
    }
    IOSkywalkPacket *pkt = nullptr;
    IOReturn r = pool->allocatePacket(1, &pkt, 1 /* no sleep */);
    if (r != kIOReturnSuccess || pkt == nullptr) {
        gRxDlv[kRxDlvAllocFail]++;
        if (++gRxDlv[kRxDlvConsecAlloc] >= 8)
            gRxDlv[kRxDlvStopped] = 1;
        return 4;
    }
    gRxDlv[kRxDlvConsecAlloc] = 0;
    gRxDlv[kRxDlvStateAlloc] = airplayPktState(pkt);
    r = airplayPktPrepareWithQueue(pkt, nullptr, kIOSkywalkPacketDirectionRx);   /* AWRXDELIVER4: no source queue */
    gRxDlv[kRxDlvPrepRes] = (UInt32)r;
    gRxDlv[kRxDlvStatePrep] = airplayPktState(pkt);
    if (r != kIOReturnSuccess) {
        gRxDlv[kRxDlvPrepFail]++;
        airplayRxDlvSnap(pkt, nullptr, 0, nullptr, 0);
        pool->deallocatePacket(pkt);
        return 9;
    }
    IOSkywalkPacketBuffer *buf = nullptr;
    const UInt32 nb = pkt->getPacketBuffers(&buf, 1);
    IOMemoryDescriptor *md = nullptr;
    UInt64 wOff = 0;
    if (nb == 1 && buf != nullptr && buf->mMemorySegment != nullptr) {
        memcpy(&md, reinterpret_cast<unsigned char *>(buf->mMemorySegment) + 32, sizeof(md));
        wOff = buf->mMemorySegmentOffset;
    }
    if (md == nullptr) {
        gRxDlv[kRxDlvBufFailSeg]++;
        airplayRxDlvSnap(pkt, buf, nb, nullptr, 0);
        md = pkt->getMemoryDescriptor();                       /* fallback, bounded below */
        wOff = 0;
        if (md != nullptr)
            gRxDlv[kRxDlvViaPktMd]++;
    }
    if (md == nullptr || wOff + total > md->getLength()) {
        if (md != nullptr) {
            gRxDlv[kRxDlvBufFailLen]++;
            airplayRxDlvSnap(pkt, buf, nb, md, wOff);
        }
        gRxDlv[kRxDlvBufFail]++;
        pool->deallocatePacket(pkt);
        return 5;
    }
    uint8_t eh[14];
    memcpy(eh, dst, 6);
    memcpy(eh + 6, src, 6);
    eh[12] = etherType[0];
    eh[13] = etherType[1];
    if (md->writeBytes(wOff, eh, 14) != 14 ||
        md->writeBytes(wOff + 14, payload, payloadLen) != payloadLen) {
        gRxDlv[kRxDlvWriteFail]++;
        pool->deallocatePacket(pkt);
        return 7;
    }
    pkt->setDataOffsetAndLength(0, (UInt32)total);

    /* INPUTFEED-20261017: hand the frame to IO80211's AWDL peer-input path (default OFF). */
    if (gInputFeedOn < 0) {
        gInputFeedOn = 0; /* RXFIX-20261024: INPUTFEED default OFF (bad inputPacket cast) */
        gFeed[kFeedOn] = (UInt32)gInputFeedOn;
    }
    gInputFeedOn = 0; gFeed[kFeedOn] = 0; /* RXFIX-20261024: force INPUTFEED off; enqueuePackets only */
    if (gInputFeedOn) {
        gFeed[kFeedCalls]++;
        if (gAirplayAWDLIface == nullptr) {
            gFeed[kFeedIfaceNull]++;
        } else {
            uint8_t pinfo[64];
            for (unsigned int i = 0; i < sizeof(pinfo); i++)
                pinfo[i] = 0;
            bool consumed = false;
            IOReturn fr = gAirplayAWDLIface->inputPacket(
                reinterpret_cast<IO80211NetworkPacket *>(pkt),
                reinterpret_cast<packet_info_tag *>(pinfo),
                reinterpret_cast<ether_header *>(eh),
                &consumed);
            gFeed[kFeedLastRet] = (UInt32)fr;
            if (consumed) {
                /* IO80211 took ownership (PPP-wait queue). Do NOT enqueue or free. */
                gFeed[kFeedConsumed]++;
                gRxDlv[kRxDlvOk]++;
                if (dst[0] & 0x01) gRxDlv[kRxDlvMcast]++; else gRxDlv[kRxDlvUcast]++;
                gRxDlv[kRxDlvLastEtherType] = ((UInt32)etherType[0] << 8) | etherType[1];
                gRxDlv[kRxDlvLastLen] = (UInt32)total;
                return 0;
            }
            /* not consumed: packet still ours -> fall through to the normal BPF enqueue. */
            gFeed[kFeedNotConsumed]++;
        }
    }

    const IOSkywalkPacket *pkts[1] = { pkt };
    r = rxc->enqueuePackets(pkts, 1, 0);
    gRxDlv[kRxDlvLastEnq] = (UInt32)r;
    if (r != kIOReturnSuccess) {
        gRxDlv[kRxDlvEnqFail]++;
        pool->deallocatePacket(pkt);
        return 8;
    }
    gRxDlv[kRxDlvOk]++;
    if (dst[0] & 0x01)
        gRxDlv[kRxDlvMcast]++;
    else
        gRxDlv[kRxDlvUcast]++;
    gRxDlv[kRxDlvLastEtherType] = ((UInt32)etherType[0] << 8) | etherType[1];
    gRxDlv[kRxDlvLastLen] = (UInt32)total;
    return 0;
}

static bool
airplayRegisterNativeAWDL(AirportItlwmAWDLInterface *awdl)
{
    IOLog(
        "AIRPLAY AWDL TRACE: ENTER airplayRegisterNativeAWDL this=%p\\n",
        awdl
    );
    if (awdl == nullptr)
        return false;
    gAirplayAWDLIface = awdl; /* INPUTFEED-20261017 */

    // Initialize before queue creation so untouched callbacks report zero.
    awdl->setProperty("AIRPLAYQueueTxSubmissionCallsSampled", (unsigned long long)0, 32);
    awdl->setProperty("AIRPLAYQueueTxSubmissionLastCountArg", (unsigned long long)0, 32);
    awdl->setProperty("AIRPLAYQueueTxSubmissionCountArgTotalSampled", (unsigned long long)0, 32);
    awdl->setProperty("AIRPLAYQueueTxCompletionCallsSampled", (unsigned long long)0, 32);
    awdl->setProperty("AIRPLAYQueueTxCompletionLastCountArg", (unsigned long long)0, 32);
    awdl->setProperty("AIRPLAYQueueTxCompletionCountArgTotalSampled", (unsigned long long)0, 32);
    awdl->setProperty("AIRPLAYQueueRxSubmissionCallsSampled", (unsigned long long)0, 32);
    awdl->setProperty("AIRPLAYQueueRxSubmissionLastCountArg", (unsigned long long)0, 32);
    awdl->setProperty("AIRPLAYQueueRxSubmissionCountArgTotalSampled", (unsigned long long)0, 32);
    awdl->setProperty("AIRPLAYQueueRxCompletionCallsSampled", (unsigned long long)0, 32);
    awdl->setProperty("AIRPLAYQueueRxCompletionLastCountArg", (unsigned long long)0, 32);
    awdl->setProperty("AIRPLAYQueueRxCompletionCountArgTotalSampled", (unsigned long long)0, 32);
    awdl->setProperty("AIRPLAYQueueProbeVersion", (unsigned long long)1, 32);
    awdl->setProperty("AIRPLAYQueueProbeSampleLimit", (unsigned long long)32, 32);

    IOLog(
        "AIRPLAY AWDL NATIVE: registration ENTER this=%p\n",
        awdl
    );

    /*
     * Temporary first-test pool sizing.
     *
     * These values are deliberately NOT claimed to be native
     * Broadcom constants.  They are retained from the old
     * known-compiling experiment simply to isolate the registration
     * question from a second pool-sizing experiment.
     *
     * A 2048-byte single-buffer packet comfortably contains the
     * native AWDL registration MTU value (1428).
     */
    IOSkywalkPacketBufferPool::PoolOptions poolOptions = {};
    poolOptions.packetCount = 64;
    poolOptions.bufferCount = 64;
    poolOptions.bufferSize = 2048;
    poolOptions.maxBuffersPerPacket = 1;
    poolOptions.memorySegmentSize = 0;
    poolOptions.poolFlags = 1;
    poolOptions.pad = 0;

    IOSkywalkPacketBufferPool *pool =
        IOSkywalkPacketBufferPool::withName(
            "AirportItlwmAWDL",
            awdl,
            1,
            &poolOptions
        );

    if (pool == nullptr) {
        IOLog("AIRPLAY AWDL NATIVE: pool creation FAILED\n");
        return false;
    }

    IOSkywalkTxSubmissionQueue *txSubmission =
        IOSkywalkTxSubmissionQueue::withPool(
            pool,
            64,
            0,
            awdl,
            &airplayAWDLTxSubmission,
            nullptr,
            1
        );

    IOSkywalkTxCompletionQueue *txCompletion =
        IOSkywalkTxCompletionQueue::withPool(
            pool,
            64,
            0,
            awdl,
            &airplayAWDLTxCompletion,
            nullptr,
            0
        );

    IOSkywalkRxSubmissionQueue *rxSubmission =
        IOSkywalkRxSubmissionQueue::withPool(
            pool,
            64,
            0,
            0,
            awdl,
            &airplayAWDLRxSubmission,
            nullptr,
            0
        );

    IOSkywalkRxCompletionQueue *rxCompletion =
        IOSkywalkRxCompletionQueue::withPool(
            pool,
            64,
            0,
            awdl,
            &airplayAWDLRxCompletion,
            nullptr,
            0
        );

    if (txSubmission == nullptr ||
        txCompletion == nullptr ||
        rxSubmission == nullptr ||
        rxCompletion == nullptr) {

        IOLog(
            "AIRPLAY AWDL NATIVE: queue creation FAILED "
            "txs=%p txc=%p rxs=%p rxc=%p\n",
            txSubmission,
            txCompletion,
            rxSubmission,
            rxCompletion
        );

        if (txSubmission != nullptr)
            txSubmission->release();

        if (txCompletion != nullptr)
            txCompletion->release();

        if (rxSubmission != nullptr)
            rxSubmission->release();

        if (rxCompletion != nullptr)
            rxCompletion->release();

        pool->release();
        return false;
    }

    IOSkywalkPacketQueue *queues[4] = {
        txSubmission,
        txCompletion,
        rxSubmission,
        rxCompletion
    };

    IOSkywalkEthernetInterface::RegistrationInfo info = {};
    memset(&info, 0, sizeof(info));

    if (!awdl->initRegistrationInfo(
            &info,
            1,
            sizeof(info))) {

        IOLog(
            "AIRPLAY AWDL NATIVE: initRegistrationInfo FAILED\n"
        );

        txSubmission->release();
        txCompletion->release();
        rxSubmission->release();
        rxCompletion->release();
        pool->release();
        return false;
    }

    /*
     * Sonoma 14.8.7 native AWDL RegistrationInfo layout recovered
     * from the BCM reference implementation.
     *
     * initRegistrationInfo() establishes the base structure first.
     * We then apply only fields for which we have strong native AWDL
     * evidence.
     */
    UInt8 *raw = reinterpret_cast<UInt8 *>(&info);

    *reinterpret_cast<UInt32 *>(raw + 0x0c) = 3;
    *reinterpret_cast<UInt32 *>(raw + 0x14) = 2;

    *reinterpret_cast<UInt32 *>(raw + 0x24) = 0x80;
    *reinterpret_cast<UInt32 *>(raw + 0x28) = 0x80;

    *reinterpret_cast<const char **>(raw + 0x30) = "awdl";

    *reinterpret_cast<UInt32 *>(raw + 0x38) = 0;
    *reinterpret_cast<UInt32 *>(raw + 0x3c) = 0x40;

    *reinterpret_cast<UInt32 *>(raw + 0x40) = 6;

    awdl->setProperty(
        "AIRPLAYRegistrationInfo40",
        (unsigned long long)6,
        32
    );

    *reinterpret_cast<UInt32 *>(raw + 0x48) = 1428;
    *reinterpret_cast<UInt32 *>(raw + 0x4c) = 1428;

#if __IO80211_TARGET >= __MAC_14_4
    ether_addr selfAddress = awdl->getSelfMacAddr();

    memcpy(
        raw + 0x108,
        selfAddress.octet,
        sizeof(selfAddress.octet)
    );
#else
    ether_addr *selfAddress = awdl->getSelfMacAddr();

    if (selfAddress == nullptr) {
        IOLog(
            "AIRPLAY AWDL NATIVE: getSelfMacAddr returned NULL\n"
        );

        txSubmission->release();
        txCompletion->release();
        rxSubmission->release();
        rxCompletion->release();
        pool->release();
        return false;
    }

    memcpy(
        raw + 0x108,
        selfAddress->octet,
        sizeof(selfAddress->octet)
    );
#endif

    /*
     * Prime the V2 getter bridge before native registration.
     * registerEthernetInterface() may query these virtual getters
     * while registration is in progress.
     */
    gAirplayAWDLNativePool = pool;
    gAirplayAWDLNativeTxSubmission = txSubmission;
    gAirplayAWDLNativeTxCompletion = txCompletion;
    gAirplayAWDLNativeRxSubmission = rxSubmission;
    gAirplayAWDLNativeRxCompletion = rxCompletion;

    awdl->setProperty(
        "AIRPLAYNativeResourceBridgePrimed",
        (unsigned long long)1,
        8
    );

    IOLog(
        "AIRPLAY AWDL NATIVE: calling registerEthernetInterface "
        "queues=4 pool=%p\n",
        pool
    );

    IOReturn registerResult =
        awdl->registerEthernetInterface(
            &info,
            queues,
            4,
            pool,
            pool,
            0
        );

    awdl->setProperty("AIRPLAYNativeRegistrationResult",
                      (unsigned long long)(UInt32)registerResult, 32);

    IOLog(
        "AIRPLAY AWDL NATIVE: registerEthernetInterface "
        "RETURN=0x%x\n",
        registerResult
    );

    /*
     * On failure nothing should own our resource references.
     * Release everything.
     *
     * On success intentionally retain our creation references for
     * this first boot experiment.  This avoids introducing a lifetime
     * assumption before we verify native registration.  It is a tiny
     * one-interface leak that disappears on reboot and can be cleaned
     * up once registration is proven.
     */
    if (registerResult != kIOReturnSuccess) {
        gAirplayAWDLNativePool = nullptr;
        gAirplayAWDLNativeTxSubmission = nullptr;
        gAirplayAWDLNativeTxCompletion = nullptr;
        gAirplayAWDLNativeRxSubmission = nullptr;
        gAirplayAWDLNativeRxCompletion = nullptr;

        txSubmission->release();
        txCompletion->release();
        rxSubmission->release();
        rxCompletion->release();
        pool->release();
        return false;
    }


    /*
     * SONOMA NATIVE QUEUE BINDING REPAIR
     *
     * registerInterfaceWithQueues() normally calls
     * IOSkywalkPacketQueue::setInterface(this) for each queue.
     *
     * Our registerEthernetInterface() returns success and creates
     * QueueSet/kern-netif state, but leaves every queue's interface
     * pointer NULL. Complete only that missing relationship here.
     *
     * Do NOT enable queues or request/dequeue packets here.
     */
    awdl->setProperty(
        "AIRPLAYNativeQueueBindAttempted",
        (unsigned long long)1,
        8
    );

    IOSkywalkPacketQueue *bindQueues[4] = {
        txSubmission,
        txCompletion,
        rxSubmission,
        rxCompletion
    };

    UInt32 nativeQueueBindCount = 0;

    for (UInt32 i = 0; i < 4; i++) {
        IOSkywalkPacketQueue *queue = bindQueues[i];

        if (queue == nullptr)
            continue;

        IOSkywalkInterface *boundInterface =
            *reinterpret_cast<IOSkywalkInterface **>(
                reinterpret_cast<unsigned char *>(queue) + 0x70
            );

        if (boundInterface == nullptr) {
            queue->setInterface(
                static_cast<IOSkywalkInterface *>(awdl)
            );
            nativeQueueBindCount++;
        }
    }

    awdl->setProperty(
        "AIRPLAYNativeQueueBindCount",
        (unsigned long long)nativeQueueBindCount,
        32
    );


    /*
     * Diagnostic only:
     * verify what Skywalk populated after successful
     * registerEthernetInterface().
     */
    awdl->setProperty(
        "AIRPLAYPostRegExpansion1",
        (unsigned long long)(awdl->mExpansionData != nullptr ? 1 : 0),
        8
    );

    awdl->setProperty(
        "AIRPLAYPostRegExpansion2",
        (unsigned long long)(awdl->mExpansionData2 != nullptr ? 1 : 0),
        8
    );

    awdl->setProperty(
        "AIRPLAYPostRegInfo1",
        (unsigned long long)(
            awdl->mExpansionData != nullptr &&
            awdl->mExpansionData->fRegistrationInfo != nullptr ? 1 : 0
        ),
        8
    );

    awdl->setProperty(
        "AIRPLAYPostRegInfo2",
        (unsigned long long)(
            awdl->mExpansionData2 != nullptr &&
            awdl->mExpansionData2->fRegistrationInfo != nullptr ? 1 : 0
        ),
        8
    );


    /*
     * Diagnostic only:
     * inspect canonical Skywalk resources after successful registration.
     */
    void *postTxPool =
        awdl->IO80211SkywalkInterface::getTxPacketPool();

    void *postRxPool =
        awdl->IO80211SkywalkInterface::getRxPacketPool();

    void *postTxComp =
        awdl->IO80211SkywalkInterface::getTxCompQueue();

    void *postRxComp =
        awdl->IO80211SkywalkInterface::getRxCompQueue();

    int postNumTxQueues =
        awdl->IO80211SkywalkInterface::getNumTxQueues();

    awdl->setProperty(
        "AIRPLAYPostRegTxPool",
        (unsigned long long)(postTxPool != nullptr ? 1 : 0),
        8
    );

    awdl->setProperty(
        "AIRPLAYPostRegRxPool",
        (unsigned long long)(postRxPool != nullptr ? 1 : 0),
        8
    );

    awdl->setProperty(
        "AIRPLAYPostRegTxComp",
        (unsigned long long)(postTxComp != nullptr ? 1 : 0),
        8
    );

    awdl->setProperty(
        "AIRPLAYPostRegRxComp",
        (unsigned long long)(postRxComp != nullptr ? 1 : 0),
        8
    );

    awdl->setProperty(
        "AIRPLAYPostRegNumTxQueues",
        (unsigned long long)(uint32_t)postNumTxQueues,
        32
    );


    /*
     * TX BINDING AUDIT
     *
     * Sonoma IOSkywalkInterface::registerInterfaceWithQueues()
     * calls IOSkywalkPacketQueue::setInterface(this) for every
     * registered queue.
     *
     * Broadcom also has a dedicated
     * AppleBCMWLANSkywalkTxSubmissionQueue::setInterface().
     *
     * Do not change queue state here.  Only verify the object graph
     * produced by our successful registerEthernetInterface().
     */
    IOSkywalkInterface *nativeTxBoundInterface =
        (*reinterpret_cast<IOSkywalkInterface **>(reinterpret_cast<unsigned char *>(txSubmission) + 112));

    IOWorkLoop *nativeTxAccessorWorkLoop =
        txSubmission->getWorkLoop();

    void *nativeTxRefcon =
        (*reinterpret_cast<void **>(reinterpret_cast<unsigned char *>(txSubmission) + 88));

    IOSkywalkPacketBufferPool *nativeTxAccessorPool =
        txSubmission->getPacketBufferPool();

    awdl->setProperty(
        "AIRPLAYNativeTxBoundInterfacePresent",
        (unsigned long long)(
            nativeTxBoundInterface != nullptr ? 1 : 0
        ),
        8
    );

    awdl->setProperty(
        "AIRPLAYNativeTxBoundInterfaceIsAWDL",
        (unsigned long long)(
            nativeTxBoundInterface ==
            static_cast<IOSkywalkInterface *>(awdl) ? 1 : 0
        ),
        8
    );

    awdl->setProperty(
        "AIRPLAYNativeTxAccessorWorkLoopPresent",
        (unsigned long long)(
            nativeTxAccessorWorkLoop != nullptr ? 1 : 0
        ),
        8
    );

    awdl->setProperty(
        "AIRPLAYNativeTxEventSourceEnabled",
        (unsigned long long)(
            txSubmission->isEnabled() ? 1 : 0
        ),
        8
    );

    awdl->setProperty(
        "AIRPLAYNativeTxAccessorReady",
        (unsigned long long)(
            (*reinterpret_cast<bool *>(reinterpret_cast<unsigned char *>(txSubmission) + 188)) ? 1 : 0
        ),
        8
    );

    awdl->setProperty(
        "AIRPLAYNativeTxRefconPresent",
        (unsigned long long)(
            nativeTxRefcon != nullptr ? 1 : 0
        ),
        8
    );

    awdl->setProperty(
        "AIRPLAYNativeTxAccessorPoolPresent",
        (unsigned long long)(
            nativeTxAccessorPool != nullptr ? 1 : 0
        ),
        8
    );

    awdl->setProperty(
        "AIRPLAYNativeTxAccessorPoolMatches",
        (unsigned long long)(
            nativeTxAccessorPool == pool ? 1 : 0
        ),
        8
    );

    awdl->setProperty(
        "AIRPLAYNativeTxQueueId",
        (unsigned long long)(*reinterpret_cast<UInt32 *>(reinterpret_cast<unsigned char *>(txSubmission) + 152)),
        32
    );

    awdl->setProperty(
        "AIRPLAYNativeTxCapacity",
        (unsigned long long)(*reinterpret_cast<UInt32 *>(reinterpret_cast<unsigned char *>(txSubmission) + 156)),
        32
    );

    IOLog(
        "AIRPLAY AWDL NATIVE: registration SUCCESS this=%p\n",
        awdl
    );

    return true;
}


bool
AirportItlwmAWDLInterface::attach(IOService *provider)
{
    airplayLifeProperty(this, "AIRPLAYLifeAttachEnter", 1);
    IOLog(
        "AIRPLAY AWDL LIFE: attach ENTER this=%p provider=%p\n",
        this,
        provider
    );

    bool result =
        IO80211VirtualInterface::attach(provider);

    IOLog(
        "AIRPLAY AWDL LIFE: attach RETURN=%d this=%p\n",
        result,
        this
    );

    airplayLifeProperty(
        this,
        "AIRPLAYLifeAttachReturn",
        result ? 1 : 0
    );

    return result;
}


bool
AirportItlwmAWDLInterface::start(IOService *provider)
{
    /* UMI-DIAG-V1: initialize zeros so absence is distinguishable from idle. */
    setProperty("AIRPLAYUmiProbeVersion", (unsigned long long)1, 32);
    setProperty("AIRPLAYUmi149Calls", (unsigned long long)gUmi149Calls, 32);
    setProperty("AIRPLAYUmi149Return", (unsigned long long)0, 32);
    setProperty("AIRPLAYUmi69Calls", (unsigned long long)gUmi69Calls, 32);
    setProperty("AIRPLAYUmi69Acked", (unsigned long long)gUmi69Acked, 32);
    setProperty("AIRPLAYUmi69Failed", (unsigned long long)gUmi69Failed, 32);
    setProperty("AIRPLAYUmi69Invalid", (unsigned long long)gUmi69Invalid, 32);
    airplayLifeProperty(this, "AIRPLAYLifeStartEnter", 1);
    IOLog(
        "AIRPLAY AWDL LIFE: start ENTER this=%p provider=%p\n",
        this,
        provider
    );

    /*
     * PRE-START REGISTRATIONINFO A/B
     *
     * The normal Sonoma primary-interface path persists RegistrationInfo
     * into both Skywalk expansion records before start().
     *
     * Do NOT move native queue registration yet.  This experiment only
     * seeds those persistent RegistrationInfo records before the inherited
     * start() so we can see whether that changes Skywalk/BSD materialization.
     */

    setProperty(
        "AIRPLAYPreStartExpansion1",
        (unsigned long long)(mExpansionData != nullptr ? 1 : 0),
        8
    );

    setProperty(
        "AIRPLAYPreStartExpansion2",
        (unsigned long long)(mExpansionData2 != nullptr ? 1 : 0),
        8
    );

    setProperty(
        "AIRPLAYPreStartInfo1",
        (unsigned long long)(
            mExpansionData != nullptr &&
            mExpansionData->fRegistrationInfo != nullptr ? 1 : 0
        ),
        8
    );

    setProperty(
        "AIRPLAYPreStartInfo2",
        (unsigned long long)(
            mExpansionData2 != nullptr &&
            mExpansionData2->fRegistrationInfo != nullptr ? 1 : 0
        ),
        8
    );

    bool preStartSeedAttempted = false;
    bool preStartSeedResult = false;

    if (mExpansionData != nullptr &&
        mExpansionData2 != nullptr &&
        mExpansionData->fRegistrationInfo == nullptr &&
        mExpansionData2->fRegistrationInfo == nullptr) {

        preStartSeedAttempted = true;

        IOSkywalkEthernetInterface::RegistrationInfo preInfo = {};
        memset(&preInfo, 0, sizeof(preInfo));

        bool preInfoReady =
            initRegistrationInfo(
                &preInfo,
                1,
                sizeof(preInfo)
            );

        /*
         * VANILLA-REGINFO experiment:
         *
         * Keep initRegistrationInfo() completely untouched before
         * IO80211VirtualInterface::start().
         *
         * Previous build successfully persisted both expansion records,
         * but the BCM-derived raw-field overrides still resulted in:
         *   TxPool = 0
         *   RxPool = 0
         *   TxComp = 0
         *   RxComp = 0
         *   NumTxQueues = 0
         *
         * Let Sonoma consume its own RegistrationInfo layout unchanged.
         * The later manual AWDL registration remains enabled for this
         * experiment so only the pre-start contract changes.
         */
        setProperty(
            "AIRPLAYPreStartVanillaInfo",
            (unsigned long long)(preInfoReady ? 1 : 0),
            8
        );

        if (preInfoReady) {
            void *copy1 = IOMalloc(sizeof(preInfo));
            void *copy2 = IOMalloc(sizeof(preInfo));

            if (copy1 != nullptr && copy2 != nullptr) {
                memcpy(copy1, &preInfo, sizeof(preInfo));
                memcpy(copy2, &preInfo, sizeof(preInfo));

                mExpansionData->fRegistrationInfo =
                    reinterpret_cast<
                        IOSkywalkNetworkInterface::RegistrationInfo *
                    >(copy1);

                mExpansionData2->fRegistrationInfo =
                    reinterpret_cast<
                        IOSkywalkEthernetInterface::RegistrationInfo *
                    >(copy2);

                preStartSeedResult = true;
            } else {
                if (copy1 != nullptr)
                    IOFree(copy1, sizeof(preInfo));

                if (copy2 != nullptr)
                    IOFree(copy2, sizeof(preInfo));
            }
        }
    }

    setProperty(
        "AIRPLAYPreStartSeedAttempted",
        (unsigned long long)(preStartSeedAttempted ? 1 : 0),
        8
    );

    setProperty(
        "AIRPLAYPreStartSeedResult",
        (unsigned long long)(preStartSeedResult ? 1 : 0),
        8
    );

    bool result =
        IO80211VirtualInterface::start(provider);

    setProperty(
        "AIRPLAYAfterSuperStartExpansion1",
        (unsigned long long)(mExpansionData != nullptr ? 1 : 0),
        8
    );

    setProperty(
        "AIRPLAYAfterSuperStartExpansion2",
        (unsigned long long)(mExpansionData2 != nullptr ? 1 : 0),
        8
    );

    setProperty(
        "AIRPLAYAfterSuperStartInfo1",
        (unsigned long long)(
            mExpansionData != nullptr &&
            mExpansionData->fRegistrationInfo != nullptr ? 1 : 0
        ),
        8
    );

    setProperty(
        "AIRPLAYAfterSuperStartInfo2",
        (unsigned long long)(
            mExpansionData2 != nullptr &&
            mExpansionData2->fRegistrationInfo != nullptr ? 1 : 0
        ),
        8
    );

    void *afterSuperTxPool =
        IO80211SkywalkInterface::getTxPacketPool();

    void *afterSuperRxPool =
        IO80211SkywalkInterface::getRxPacketPool();

    void *afterSuperTxComp =
        IO80211SkywalkInterface::getTxCompQueue();

    void *afterSuperRxComp =
        IO80211SkywalkInterface::getRxCompQueue();

    int afterSuperNumTxQueues =
        IO80211SkywalkInterface::getNumTxQueues();

    setProperty(
        "AIRPLAYAfterSuperStartTxPool",
        (unsigned long long)(afterSuperTxPool != nullptr ? 1 : 0),
        8
    );

    setProperty(
        "AIRPLAYAfterSuperStartRxPool",
        (unsigned long long)(afterSuperRxPool != nullptr ? 1 : 0),
        8
    );

    setProperty(
        "AIRPLAYAfterSuperStartTxComp",
        (unsigned long long)(afterSuperTxComp != nullptr ? 1 : 0),
        8
    );

    setProperty(
        "AIRPLAYAfterSuperStartRxComp",
        (unsigned long long)(afterSuperRxComp != nullptr ? 1 : 0),
        8
    );

    setProperty(
        "AIRPLAYAfterSuperStartNumTxQueues",
        (unsigned long long)(uint32_t)afterSuperNumTxQueues,
        32
    );

    IOLog(
        "AIRPLAY AWDL LIFE: start RETURN=%d this=%p\n",
        result,
        this
    );

    airplayLifeProperty(
        this,
        "AIRPLAYLifeStartReturn",
        result ? 1 : 0
    );

    if (result) {
        setProperty(
            "AIRPLAYNativeRegistrationSuppressed",
            (unsigned long long)0,
            8
        );

        airplayLifeProperty(
            this,
            "AIRPLAYNativeRegistrationCalled",
            1
        );

        bool nativeRegistered =
            airplayRegisterNativeAWDL(this);

        setProperty(
            "AIRPLAYNativeRegistrationSucceeded",
            (unsigned long long)(nativeRegistered ? 1 : 0),
            8
        );

        IOLog(
            "AIRPLAY AWDL LIFE: native registration RETURN=%d this=%p\n",
            nativeRegistered ? 1 : 0,
            this
        );

        registerService(kIOServiceSynchronous);
        setRunningState(false);

        /*
         * KGP-style lifecycle ordering, using the existing Sonoma queue arm:
         * attach the TX completion event source at the end of start(), before
         * normal post-start TX. pendingPackets() retains its original
         * fallback path if the controller workloop is not available yet.
         * Never retain Skywalk packet pointers for deferred retry.
         */
        if (nativeRegistered && gAirplayAWDLNativeTxCompletion != nullptr) {
            AirportItlwm *controller =
                OSDynamicCast(AirportItlwm, getProvider());
            IOWorkLoop *workLoop = controller != nullptr
                ? controller->getWorkLoop() : nullptr;
            IOReturn earlyArmResult = kIOReturnNotReady;

            if (workLoop != nullptr) {
                if (gAirplayAWDLNativeTxCompletion->getWorkLoop() == nullptr)
                    earlyArmResult = workLoop->addEventSource(
                        gAirplayAWDLNativeTxCompletion);
                else
                    earlyArmResult = kIOReturnSuccess;

                if (earlyArmResult == kIOReturnSuccess)
                    gAirplayAWDLNativeTxCompletion->enable();
            }
            setProperty("AIRPLAYNativeTxCompEarlyArmResult",
                        (unsigned long long)(UInt32)earlyArmResult, 32);
        }
        /* AWRXDELIVER5: attach + enable the RX completion queue (never armed before). */
        if (nativeRegistered && gAirplayAWDLNativeRxCompletion != nullptr) {
            int v = 0;
            const bool rxOff = PE_parse_boot_argn("-awdlrxdeliveroff", &v, sizeof(v));
            AirportItlwm *rxController = OSDynamicCast(AirportItlwm, getProvider());
            IOWorkLoop *rxWorkLoop = rxController != nullptr ? rxController->getWorkLoop() : nullptr;
            IOReturn rxArm = kIOReturnNotReady;
            if (rxOff) {
                rxArm = kIOReturnUnsupported;
            } else if (rxWorkLoop != nullptr) {
                if (gAirplayAWDLNativeRxCompletion->getWorkLoop() == nullptr)
                    rxArm = rxWorkLoop->addEventSource(gAirplayAWDLNativeRxCompletion);
                else
                    rxArm = kIOReturnSuccess;
                if (rxArm == kIOReturnSuccess)
                    gAirplayAWDLNativeRxCompletion->enable();
            }
            setProperty("AIRPLAYNativeRxCompArmResult", (unsigned long long)(UInt32)rxArm, 32);
            setProperty("AIRPLAYNativeRxCompWorkLoop",
                        (unsigned long long)(gAirplayAWDLNativeRxCompletion->getWorkLoop() != nullptr ? 1 : 0), 8);
        }
    }

    return result;
}


IOReturn
AirportItlwmAWDLInterface::enable(UInt value)
{
    airplayLifeProperty(this, "AIRPLAYLifeEnableEnter", 1);

    IOLog(
        "AIRPLAY AWDL LIFE: enable ENTER this=%p value=%u\n",
        this,
        (unsigned int)value
    );

    IOReturn result =
        IO80211VirtualInterface::enable(value);

    IOLog(
        "AIRPLAY AWDL LIFE: enable RETURN=0x%x this=%p\n",
        result,
        this
    );

    airplayLifeProperty(
        this,
        "AIRPLAYLifeEnableReturn",
        result == kIOReturnSuccess ? 1 : 0
    );

    return result;
}

/* NOMONITOR-20261014: thread currently inside IO80211VirtualInterface::setInterfaceEnable() on awdl0. */
static thread_t gAirplayBpfEnableThread = nullptr;
static UInt32 gAirplayBpfGuardEnableCalls = 0;
static UInt32 gAirplayBpfGuardSuppressed = 0;

SInt32
AirportItlwmAWDLInterface::setInterfaceEnable(bool enabled)
{
    airplayLifeProperty(this, "AIRPLAYLifeSetEnableEnter", 1);

    IOLog(
        "AIRPLAY AWDL LIFE: setInterfaceEnable ENTER this=%p enabled=%d\n",
        this,
        enabled
    );

    /* NOMONITOR: Apple's allocBpfResources() (called inside this) takes its monitor packet from
     * getTxPacketPool(); keep it off the native pool so no unbacked monitor packet is created. */
    gAirplayBpfGuardEnableCalls++;
    gAirplayBpfEnableThread = current_thread();
    SInt32 result =
        IO80211VirtualInterface::setInterfaceEnable(enabled);
    gAirplayBpfEnableThread = nullptr;
    setProperty("AIRPLAYBpfGuardEnableCalls", (unsigned long long)gAirplayBpfGuardEnableCalls, 32);
    setProperty("AIRPLAYBpfGuardSuppressed", (unsigned long long)gAirplayBpfGuardSuppressed, 32);

    /*
     * Sonoma 14.8.7 / IO80211Family 1200.13.0 only. Read-only, one-shot
     * lifecycle probe: does Apple's BPF monitor packet already have backing
     * immediately after superclass enable? Never prepare/free/replace it.
     * The offsets below come from the exact archived Apple binary.
     */
    if (enabled && result == kIOReturnSuccess) {
        const uint8_t *bpfExpansion =
            *reinterpret_cast<uint8_t *const *>(
                reinterpret_cast<const uint8_t *>(this) + 0x118);
        IOSkywalkPacket *monitor = bpfExpansion != nullptr
            ? *reinterpret_cast<IOSkywalkPacket *const *>(bpfExpansion + 0x60)
            : nullptr;
        UInt32 backing = 0; /* 0: absent, 1: unbacked, 2: backed */
        UInt32 bufferCount = 0;
        if (monitor != nullptr) {
            backing = 1;
            bufferCount = monitor->getPacketBufferCount();

            /*
             * Exact Sonoma 14.8.7 IOSkywalkFamily packet layout only.
             * READ ONLY: acquire/prepare state, allocation flags, capacity,
             * and handle presence. No prepare/free/ownership mutation.
             * Verified against archived IOSkywalkPacket machine code.
             */
            const UInt8 *bytes = reinterpret_cast<const UInt8 *>(monitor);
            const UInt32 state = *reinterpret_cast<const UInt16 *>(bytes + 0x58);
            const UInt32 acquireFlags = *reinterpret_cast<const UInt32 *>(bytes + 0x5c);
            const UInt32 maxBuffers = *reinterpret_cast<const UInt32 *>(bytes + 0x60);
            const UInt32 hasHandle =
                *reinterpret_cast<const UInt64 *>(bytes + 0x28) != 0 ? 1 : 0;
            setProperty("AIRPLAYBpfMonitorPacketState", (unsigned long long)state, 32);
            setProperty("AIRPLAYBpfMonitorAcquireFlags", (unsigned long long)acquireFlags, 32);
            setProperty("AIRPLAYBpfMonitorMaxBuffers", (unsigned long long)maxBuffers, 32);
            setProperty("AIRPLAYBpfMonitorHasHandle", (unsigned long long)hasHandle, 32);

            IOSkywalkPacketBuffer *first = nullptr;
            if (monitor->getPacketBuffers(&first, 1) == 1 && first != nullptr)
                backing = 2;
        }
        setProperty("AIRPLAYBpfMonitorProbeBacking",
                    (unsigned long long)backing, 32);
        setProperty("AIRPLAYBpfMonitorBufferCount",
                    (unsigned long long)bufferCount, 32);
    }

    IOLog(
        "AIRPLAY AWDL LIFE: setInterfaceEnable RETURN=%d this=%p\n",
        result,
        this
    );

    airplayLifeProperty(
        this,
        "AIRPLAYLifeSetEnableCalled",
        1
    );

    return result;
}

SInt32
AirportItlwmAWDLInterface::setRunningState(bool running)
{
    airplayLifeProperty(this, "AIRPLAYLifeRunningEnter", 1);
    airplayLifeProperty(
        this,
        "AIRPLAYLifeRunningValue",
        running ? 1 : 0
    );

    IOLog(
        "AIRPLAY AWDL LIFE: setRunningState ENTER this=%p running=%d\n",
        this,
        running ? 1 : 0
    );

    SInt32 result =
        IO80211VirtualInterface::setRunningState(running);

    /*
     * Diagnostic experiment:
     *
     * Native Skywalk registration succeeds and AWDL reaches running=true,
     * but Sonoma has never called setDataPathState() or enableDatapath()
     * on this interface.
     *
     * Enable the already-registered datapath once, only after a successful
     * transition to running=true. No packet handling is changed here.
     */
    static UInt32 forcedDatapathAttempt = 0;

    if (running &&
        result == kIOReturnSuccess &&
        __sync_bool_compare_and_swap(&forcedDatapathAttempt, 0, 1)) {

        setProperty(
            "AIRPLAYForcedDatapathEnableAttempted",
            (unsigned long long)1,
            8
        );

        enableDatapath();

        setProperty(
            "AIRPLAYForcedDatapathEnableReturned",
            (unsigned long long)1,
            8
        );

        /*
         * Complete the Sonoma Skywalk datapath transition.
         *
         * enableDatapath() alone returns successfully but the registered
         * TX submission queue remains dormant. Explicitly move the
         * IO80211VirtualInterface datapath into the active state.
         */
        setProperty(
            "AIRPLAYForcedDataPathStateTrueAttempted",
            (unsigned long long)1,
            8
        );

        setDataPathState(true);

        setProperty(
            "AIRPLAYForcedDataPathStateTrueReturned",
            (unsigned long long)1,
            8
        );
    }

    IOLog(
        "AIRPLAY AWDL LIFE: setRunningState RETURN=%d this=%p running=%d\n",
        result,
        this,
        running ? 1 : 0
    );

    return result;
}


void
AirportItlwmAWDLInterface::setLinkState(
    IO80211LinkState state,
    UInt reason)
{
    airplayLifeProperty(this, "AIRPLAYLifeLinkStateEnter", 1);
    airplayLifeProperty(
        this,
        "AIRPLAYLifeLinkStateUp",
        state == kIO80211NetworkLinkUp ? 1 : 0
    );

    IOLog(
        "AIRPLAY AWDL LIFE: setLinkState ENTER this=%p state=%u reason=%u\\n",
        this,
        (unsigned int)state,
        (unsigned int)reason
    );

    IO80211VirtualInterface::setLinkState(state, reason);

    /*
     * Experimental AWDL BSD/media link-status bridge.
     *
     * The normal Sonoma V2 interface reports:
     *   link up   -> reportLinkStatus(3, 0x80)
     *   link down -> reportLinkStatus(1, 0)
     *
     * The AX210 AWDL interface currently reaches IO80211 link-up
     * but never gains BSD "status: active".
     */
    if (state == kIO80211NetworkLinkUp) {
        setProperty("AIRPLAYAWDLLinkStatusReportAttempted", (unsigned long long)1, 8);
        setProperty("AIRPLAYAWDLLinkStatusReportUp", (unsigned long long)1, 8);

        IOLog(
            "AIRPLAY AWDL LINKSTATUS: reportLinkStatus(3, 0x80)\n"
        );

        reportLinkStatus(3, 0x80);
    }
    else if (state == kIO80211NetworkLinkDown) {
        setProperty("AIRPLAYAWDLLinkStatusReportAttempted", (unsigned long long)1, 8);
        setProperty("AIRPLAYAWDLLinkStatusReportUp", (unsigned long long)0, 8);

        IOLog(
            "AIRPLAY AWDL LINKSTATUS: reportLinkStatus(1, 0)\n"
        );

        reportLinkStatus(1, 0);
    }

    airplayLifeProperty(this, "AIRPLAYLifeLinkStateReturn", 1);

    IOLog(
        "AIRPLAY AWDL LIFE: setLinkState RETURN this=%p state=%u reason=%u\\n",
        this,
        (unsigned int)state,
        (unsigned int)reason
    );
}


IOReturn
AirportItlwmAWDLInterface::reportDataPathEvents(
    UInt event,
    void *data,
    unsigned long length,
    bool flag
)
{
    /* UMI-DIAG-V1: observe the real status before unchanged superclass dispatch. */
    if (event == 69)
        airplayUmiObserveStatus(this, data, length);

    static UInt32 callCount = 0;
    callCount++;

    airplayLifeProperty(
        this,
        "AIRPLAYLifeReportDataPathEnter",
        1
    );

    setProperty(
        "AIRPLAYReportDPCount",
        (unsigned long long)callCount,
        32
    );

    setProperty(
        "AIRPLAYReportDPEvent",
        (unsigned long long)event,
        32
    );

    setProperty(
        "AIRPLAYReportDPLength",
        (unsigned long long)length,
        64
    );

    setProperty(
        "AIRPLAYReportDPFlag",
        (unsigned long long)(flag ? 1 : 0),
        8
    );

    IOLog(
        "AIRPLAY AWDL LIFE: reportDataPathEvents "
        "count=%u event=%u data=%p length=%lu flag=%d\n",
        (unsigned int)callCount,
        (unsigned int)event,
        data,
        length,
        flag ? 1 : 0
    );

    /*
     * Sonoma AWDL schedule observation.
     *
     * Event 195 arrives with a 0x190-byte payload, exactly matching
     * apple80211_awdl_sync_channel_sequence.
     *
     * Diagnostic only: do not modify the payload or scheduler.
     */
    if (event == 195 &&
        data != nullptr &&
        length == sizeof(struct apple80211_awdl_sync_channel_sequence)) {

        struct apple80211_awdl_sync_channel_sequence *seq =
            reinterpret_cast<struct apple80211_awdl_sync_channel_sequence *>(data);

        IOLog(
            "AIRPLAY AWDL 195 META: "
            "version=%u length=%u encoding=%u step=%u duplicate=%u fill=%u\n",
            (unsigned int)seq->version,
            (unsigned int)seq->length,
            (unsigned int)seq->encoding,
            (unsigned int)seq->step_count,
            (unsigned int)seq->duplicate_count,
            (unsigned int)seq->fill_channel
        );

        setProperty("AIRPLAY195MetaSeen", 1, 8);
        setProperty("AIRPLAY195Version",
                    (unsigned long long)seq->version, 32);
        setProperty("AIRPLAY195Length",
                    (unsigned long long)seq->length, 8);
        setProperty("AIRPLAY195Encoding",
                    (unsigned long long)seq->encoding, 8);
        setProperty("AIRPLAY195StepCount",
                    (unsigned long long)seq->step_count, 8);
        setProperty("AIRPLAY195DuplicateCount",
                    (unsigned long long)seq->duplicate_count, 8);
        setProperty("AIRPLAY195FillChannel",
                    (unsigned long long)seq->fill_channel, 8);

        /*
         * Preserve the first 64 raw bytes of the encoded channel-sequence
         * area. Diagnostic only; the event payload is not modified.
         */
        OSData *raw64 = OSData::withBytes(
            reinterpret_cast<const UInt8 *>(data) + 16,
            64
        );

        if (raw64 != nullptr) {
            setProperty("AIRPLAY195Raw64", raw64);
            raw64->release();
        }

        OSData *raw192 = OSData::withBytes(
            reinterpret_cast<const UInt8 *>(data) + 16,
            192
        );

        if (raw192 != nullptr) {
            setProperty("AIRPLAY195Raw192", raw192);
            raw192->release();
        }

        unsigned int count = seq->length;
        if (count > 16)
            count = 16;

        setProperty("AIRPLAY195DecodedCount",
                    (unsigned long long)count, 8);

        static const char *flagNames[16] = {
            "AIRPLAY195Flags00", "AIRPLAY195Flags01",
            "AIRPLAY195Flags02", "AIRPLAY195Flags03",
            "AIRPLAY195Flags04", "AIRPLAY195Flags05",
            "AIRPLAY195Flags06", "AIRPLAY195Flags07",
            "AIRPLAY195Flags08", "AIRPLAY195Flags09",
            "AIRPLAY195Flags10", "AIRPLAY195Flags11",
            "AIRPLAY195Flags12", "AIRPLAY195Flags13",
            "AIRPLAY195Flags14", "AIRPLAY195Flags15"
        };

        static const char *channelNames[16] = {
            "AIRPLAY195Channel00", "AIRPLAY195Channel01",
            "AIRPLAY195Channel02", "AIRPLAY195Channel03",
            "AIRPLAY195Channel04", "AIRPLAY195Channel05",
            "AIRPLAY195Channel06", "AIRPLAY195Channel07",
            "AIRPLAY195Channel08", "AIRPLAY195Channel09",
            "AIRPLAY195Channel10", "AIRPLAY195Channel11",
            "AIRPLAY195Channel12", "AIRPLAY195Channel13",
            "AIRPLAY195Channel14", "AIRPLAY195Channel15"
        };

        for (unsigned int i = 0; i < 16; i++) {
            UInt16 flags = 0;
            UInt8 channel = 0;

            if (i < count) {
                flags = seq->seqs[i].flags;
                channel = (UInt8)(flags & 0xff);
            }

            setProperty(flagNames[i],
                        (unsigned long long)flags, 16);
            setProperty(channelNames[i],
                        (unsigned long long)channel, 8);
        }

        for (unsigned int i = 0; i < count; i++) {
            IOLog(
                "AIRPLAY AWDL 195 SEQ: "
                "index=%u flags=0x%04x pad=0x%02x\n",
                i,
                (unsigned int)seq->seqs[i].flags,
                (unsigned int)seq->seqs[i].pad
            );
        }
    }

    IOReturn result =
        IO80211SkywalkInterface::reportDataPathEvents(
            event,
            data,
            length,
            flag
        );

    setProperty(
        "AIRPLAYReportDPResult",
        (unsigned long long)(UInt32)result,
        32
    );

    airplayLifeProperty(
        this,
        "AIRPLAYLifeReportDataPathReturn",
        1
    );

    IOLog(
        "AIRPLAY AWDL LIFE: reportDataPathEvents "
        "RETURN=0x%x count=%u\n",
        result,
        (unsigned int)callCount
    );

    return result;
}


void
AirportItlwmAWDLInterface::postMessage(
    UInt message,
    void *data,
    unsigned long length,
    bool flag
)
{
    static UInt32 callCount = 0;

    static UInt32 count42  = 0;
    static UInt32 count43  = 0;
    static UInt32 count46  = 0;
    static UInt32 count47  = 0;
    static UInt32 count65  = 0;
    static UInt32 count67  = 0;
    static UInt32 count68  = 0;
    static UInt32 count88  = 0;
    static UInt32 count94  = 0;
    static UInt32 count142 = 0;
    static UInt32 count144 = 0;
    static UInt32 count195 = 0;

    callCount++;

    setProperty(
        "AIRPLAYPostMessageCount",
        (unsigned long long)callCount,
        32
    );

    setProperty(
        "AIRPLAYPostMessageLast",
        (unsigned long long)message,
        32
    );

    setProperty(
        "AIRPLAYPostMessageLength",
        (unsigned long long)length,
        64
    );

    setProperty(
        "AIRPLAYPostMessageFlag",
        (unsigned long long)(flag ? 1 : 0),
        8
    );

    switch (message) {
        case 42:
            count42++;
            setProperty("AIRPLAYPost42Count",
                        (unsigned long long)count42, 32);
            airplayLifeProperty(this, "AIRPLAYPostMessageAWStart", 1);
            break;

        case 43:
            count43++;
            setProperty("AIRPLAYPost43Count",
                        (unsigned long long)count43, 32);
            airplayLifeProperty(this, "AIRPLAYPostMessageAWEnd", 1);
            break;

        case 46:
            count46++;
            setProperty("AIRPLAYPost46Count",
                        (unsigned long long)count46, 32);
            airplayLifeProperty(this, "AIRPLAYPostMessageSyncChanged", 1);
            break;

        case 47:
            count47++;
            setProperty("AIRPLAYPost47Count",
                        (unsigned long long)count47, 32);
            airplayLifeProperty(this, "AIRPLAYPostMessagePeerPresence", 1);
            break;

        case 65:
            count65++;
            setProperty("AIRPLAYPost65Count",
                        (unsigned long long)count65, 32);
            break;

        case 67:
            count67++;
            setProperty("AIRPLAYPost67Count",
                        (unsigned long long)count67, 32);
            airplayLifeProperty(this, "AIRPLAYPostMessageRTStart", 1);
            break;

        case 68:
            count68++;
            setProperty("AIRPLAYPost68Count",
                        (unsigned long long)count68, 32);
            airplayLifeProperty(this, "AIRPLAYPostMessageRTEnd", 1);
            break;

        case 88:
            count88++;
            setProperty("AIRPLAYPost88Count",
                        (unsigned long long)count88, 32);
            break;

        case 94:
            count94++;
            setProperty("AIRPLAYPost94Count",
                        (unsigned long long)count94, 32);
            break;

        case 142:
            count142++;
            setProperty("AIRPLAYPost142Count",
                        (unsigned long long)count142, 32);
            break;

        case 144:
            count144++;
            setProperty("AIRPLAYPost144Count",
                        (unsigned long long)count144, 32);
            break;

        case 195:
            count195++;
            setProperty("AIRPLAYPost195Count",
                        (unsigned long long)count195, 32);
            break;

        default:
            break;
    }

    IOLog(
        "AIRPLAY AWDL POST: count=%u message=%u length=%lu flag=%d\n",
        (unsigned int)callCount,
        (unsigned int)message,
        length,
        flag ? 1 : 0
    );

    IO80211VirtualInterface::postMessage(
        message,
        data,
        length,
        flag
    );
}

void
AirportItlwmAWDLInterface::enableDatapath(void)
{
    airplayLifeProperty(
        this,
        "AIRPLAYLifeEnableDatapathEnter",
        1
    );

    IOLog(
        "AIRPLAY AWDL LIFE: enableDatapath ENTER this=%p\n",
        this
    );

    IO80211SkywalkInterface::enableDatapath();

    airplayLifeProperty(
        this,
        "AIRPLAYLifeEnableDatapathReturn",
        1
    );

    IOLog(
        "AIRPLAY AWDL LIFE: enableDatapath RETURN this=%p\n",
        this
    );
}


void
AirportItlwmAWDLInterface::disableDatapath(void)
{
    airplayLifeProperty(
        this,
        "AIRPLAYLifeDisableDatapathEnter",
        1
    );

    IOLog(
        "AIRPLAY AWDL LIFE: disableDatapath ENTER this=%p\n",
        this
    );

    IO80211SkywalkInterface::disableDatapath();

    airplayLifeProperty(
        this,
        "AIRPLAYLifeDisableDatapathReturn",
        1
    );

    IOLog(
        "AIRPLAY AWDL LIFE: disableDatapath RETURN this=%p\n",
        this
    );
}


void
AirportItlwmAWDLInterface::setDataPathState(bool state)
{
    airplayLifeProperty(this, "AIRPLAYLifeDataPathEnter", 1);
    airplayLifeProperty(
        this,
        "AIRPLAYLifeDataPathValue",
        state ? 1 : 0
    );

    IOLog(
        "AIRPLAY AWDL LIFE: setDataPathState this=%p state=%d\n",
        this,
        state ? 1 : 0
    );

    IO80211VirtualInterface::setDataPathState(state);
}



IOReturn
AirportItlwmAWDLInterface::processBSDCommand(
    ifnet_t interface,
    UInt command,
    void *data
)
{
    static UInt32 callCount = 0;
    callCount++;

    setProperty(
        "AIRPLAYAWDLBSDCommandCalls",
        (unsigned long long)callCount,
        32
    );

    setProperty(
        "AIRPLAYAWDLBSDCommandLast",
        (unsigned long long)command,
        32
    );

    UInt32 generationBefore = __atomic_load_n(
        &gAirplayAWDLSetLLAddrGeneration,
        __ATOMIC_ACQUIRE
    );

    IOReturn rawResult =
        IO80211VirtualInterface::processBSDCommand(
            interface,
            command,
            data
        );

    UInt32 generationAfter = __atomic_load_n(
        &gAirplayAWDLSetLLAddrGeneration,
        __ATOMIC_ACQUIRE
    );

    SInt32 lladdrResult = __atomic_load_n(
        &gAirplayAWDLSetLLAddrLastResult,
        __ATOMIC_ACQUIRE
    );

    setProperty(
        "AIRPLAYAWDLBSDCommandLastRawResult",
        (unsigned long long)(UInt32)rawResult,
        32
    );

    IOReturn result = rawResult;

    bool normalize =
        command == SIOCSIFLLADDR &&
        rawResult == (IOReturn)EADDRNOTAVAIL &&
        generationAfter != generationBefore &&
        lladdrResult == 0;

    if (command == SIOCSIFLLADDR) {
        setProperty(
            "AIRPLAYAWDLLLAddrCommandSeen",
            (unsigned long long)1,
            8
        );

        setProperty(
            "AIRPLAYAWDLLLAddrCommandRawResult",
            (unsigned long long)(UInt32)rawResult,
            32
        );

        setProperty(
            "AIRPLAYAWDLLLAddrCommandSetterRan",
            (unsigned long long)(
                generationAfter != generationBefore ? 1 : 0
            ),
            8
        );
    }

    if (normalize) {
        result = kIOReturnSuccess;

        setProperty(
            "AIRPLAYAWDLLLAddrCommandNormalized",
            (unsigned long long)1,
            8
        );
    }

    setProperty(
        "AIRPLAYAWDLBSDCommandLastResult",
        (unsigned long long)(UInt32)result,
        32
    );

    return result;
}


void
AirportItlwmAWDLInterface::setHardwareAddress(ether_addr *address)
{
    AirportItlwm *owner = OSDynamicCast(AirportItlwm, getProvider());
    if (owner && owner->fSonomaAWDLInterface == this && owner->awdlAddressSyncEnabled()) {
        owner->awdlAddressSyncSet(this, address);
        return;
    }
    addressSyncSetHardwareOriginal(address);
}

void
AirportItlwmAWDLInterface::addressSyncSetHardwareOriginal(ether_addr *address)
{
    static UInt32 callCount = 0;
    callCount++;

    setProperty(
        "AIRPLAYAWDLSetHardwareAddressCalls",
        (unsigned long long)callCount,
        32
    );

    setProperty(
        "AIRPLAYAWDLSetHardwareAddressNonNull",
        (unsigned long long)(address != nullptr ? 1 : 0),
        8
    );

    /*
     * V2 bridge retained: native callback, then BSD address setter.
     * ADDRSYNC-V1 executes this entire bridge under the controller gate.
     * Hardware following remains deferred through the existing P2P task.
     */
    IO80211VirtualInterface::setHardwareAddress(address);

    setProperty(
        "AIRPLAYAWDLSetHardwareAddressReturned",
        (unsigned long long)1,
        8
    );

    setProperty(
        "AIRPLAYAWDLSetLLAddrIfnetAvailable",
        (unsigned long long)(gAirplayAWDLBSDIfnet != nullptr ? 1 : 0),
        8
    );

    if (address != nullptr && gAirplayAWDLBSDIfnet != nullptr) {
        errno_t result = ifnet_set_lladdr(
            gAirplayAWDLBSDIfnet,
            address,
            sizeof(*address)
        );

        setProperty(
            "AIRPLAYAWDLSetLLAddrAttempted",
            (unsigned long long)1,
            8
        );

        setProperty(
            "AIRPLAYAWDLSetLLAddrResult",
            (unsigned long long)(UInt32)result,
            32
        );

        __atomic_store_n(
            &gAirplayAWDLSetLLAddrLastResult,
            (SInt32)result,
            __ATOMIC_RELEASE
        );

        UInt32 generation = __atomic_add_fetch(
            &gAirplayAWDLSetLLAddrGeneration,
            (UInt32)1,
            __ATOMIC_RELEASE
        );

        setProperty(
            "AIRPLAYAWDLSetLLAddrGeneration",
            (unsigned long long)generation,
            32
        );
    }
}


/* DIAGSVC2-20261016: observe-only instrumentation of the AWDL service / OOB transmit IOCTLs. */
extern "C" UInt32 airplayP2PSessionActiveNow(void);
static UInt32 gDiagSvcParamsCalls = 0;
static UInt32 gDiagSvcReqCalls = 0;
static UInt32 gDiagSvcReqInSession = 0;
static UInt32 gDiagOobReqCalls = 0;
static UInt32 gDiagOobAutoCalls = 0;
static UInt32 gDiagOobInSession = 0;
static UInt32 gDiagSvcSessionSeen = 0;
static volatile UInt32 gDiagOobReqSampled = 0;
static volatile UInt32 gDiagOobAutoSampled = 0;

static void
airplayDiagSvcMeta(AirportItlwmAWDLInterface *self, int req_type, int req_val,
                   UInt32 req_len, bool isSet)
{
    const UInt32 inSess = airplayP2PSessionActiveNow();
    bool hit = false;
    switch (req_type) {
        case 119: gDiagSvcParamsCalls++; hit = true; break;
        case 120: gDiagSvcReqCalls++; if (inSess) gDiagSvcReqInSession++; hit = true; break;
        case 149: gDiagOobReqCalls++; if (inSess) gDiagOobInSession++; hit = true; break;
        case 225: gDiagOobAutoCalls++; if (inSess) gDiagOobInSession++; hit = true; break;
        default: break;
    }
    if (!hit)
        return;
    if (inSess)
        gDiagSvcSessionSeen = 1;
    self->setProperty("AIRPLAYDiagSvcParamsCalls", (unsigned long long)gDiagSvcParamsCalls, 32);
    self->setProperty("AIRPLAYDiagSvcReqCalls", (unsigned long long)gDiagSvcReqCalls, 32);
    self->setProperty("AIRPLAYDiagSvcReqInSession", (unsigned long long)gDiagSvcReqInSession, 32);
    self->setProperty("AIRPLAYDiagOobReqCalls", (unsigned long long)gDiagOobReqCalls, 32);
    self->setProperty("AIRPLAYDiagOobAutoCalls", (unsigned long long)gDiagOobAutoCalls, 32);
    self->setProperty("AIRPLAYDiagOobInSession", (unsigned long long)gDiagOobInSession, 32);
    self->setProperty("AIRPLAYDiagSvcSessionSeen", (unsigned long long)gDiagSvcSessionSeen, 32);
    self->setProperty("AIRPLAYDiagSvcLastType", (unsigned long long)req_type, 32);
    self->setProperty("AIRPLAYDiagSvcLastVal", (unsigned long long)req_val, 32);
    self->setProperty("AIRPLAYDiagSvcLastLen", (unsigned long long)req_len, 32);
    self->setProperty("AIRPLAYDiagSvcLastSet", (unsigned long long)(isSet ? 1 : 0), 8);
}

static void
airplayDiagOobSample(AirportItlwmAWDLInterface *self, const char *name,
                     const void *data, volatile UInt32 *flag)
{
    if (data == nullptr)
        return;
    if (!__sync_bool_compare_and_swap(flag, 0, 1))
        return;
    /* UMI-DIAG-V1: Apple uses a 56-byte request with a payload pointer at +48.
     * Only snapshot the fixed prefix; never dereference or publish that pointer. */
    OSData *sd = OSData::withBytes(data, 48);
    if (sd != nullptr) {
        self->setProperty(name, sd);
        sd->release();
    }
}

void
AirportItlwmAWDLInterface::handleIoctl(
    ifnet_t interface,
    unsigned long command,
    void *data
)
{
    { /* DIAGSVC2: always-present marker so idle != not-loaded */
        static volatile UInt32 sDiagMarker = 0;
        if (__sync_bool_compare_and_swap(&sDiagMarker, 0, 1))
            setProperty("AIRPLAYDiagSvcTxLoaded", (unsigned long long)1, 8);
    }
    { /* INPUTFEED-20261017: publish feed counters */
        setProperty("AIRPLAYInputFeedOn", (unsigned long long)gFeed[kFeedOn], 32);
        setProperty("AIRPLAYInputFeedCalls", (unsigned long long)gFeed[kFeedCalls], 32);
        setProperty("AIRPLAYInputFeedConsumed", (unsigned long long)gFeed[kFeedConsumed], 32);
        setProperty("AIRPLAYInputFeedNotConsumed", (unsigned long long)gFeed[kFeedNotConsumed], 32);
        setProperty("AIRPLAYInputFeedLastRet", (unsigned long long)gFeed[kFeedLastRet], 32);
        setProperty("AIRPLAYInputFeedIfaceNull", (unsigned long long)gFeed[kFeedIfaceNull], 32);
    }
    if (
        data != nullptr &&
        (
            command == SIOCSA80211 ||
            command == SIOCGA80211
        )
    ) {
        auto *req =
            reinterpret_cast<struct apple80211req *>(data);

        airplayDiagSvcMeta(this, req->req_type, req->req_val, req->req_len,
                           command == SIOCSA80211); /* DIAGSVC2 */

        if (
            command == SIOCGA80211 &&
            req->req_type == APPLE80211_IOC_SUPPORTED_CHANNELS
        ) {
            airplayLifeProperty(
                this,
                "AIRPLAYSupportedChannelsHandle",
                1
            );

            IOLog(
                "AIRPLAY SUPPORTED_CHANNELS HANDLE: "
                "command=%lu req_type=%d req_val=%d req_len=%u\\n",
                command,
                req->req_type,
                req->req_val,
                req->req_len
            );
        }

        if (req->req_type == 349 || req->req_val == 349) {
            airplayLifeProperty(this, "AIRPLAY349AWDLHandle", 1);
        }

        if (
            req->req_type == 119 ||
            req->req_type == 120 ||
            req->req_val == 119 ||
            req->req_val == 120
        ) {
            IOLog(
                "AIRPLAY IOCTL451: command=%lu "
                "req_type=%d req_val=%d req_len=%u\n",
                command,
                req->req_type,
                req->req_val,
                req->req_len
            );
        }
    }

    IO80211VirtualInterface::handleIoctl(
        interface,
        command,
        data
    );
}


void *
AirportItlwmAWDLInterface::getP2PSkywalkPeerMgr(void)
{
    airplayLifeProperty(this, "AIRPLAYLifeGetP2PPeerEnter", 1);

    void *result =
        IO80211VirtualInterface::getP2PSkywalkPeerMgr();

    IOLog(
        "AIRPLAY AWDL LIFE: getP2PSkywalkPeerMgr RETURN=%p this=%p\n",
        result,
        this
    );

    airplayLifeProperty(
        this,
        "AIRPLAYLifeGetP2PPeerNonNull",
        result != nullptr ? 1 : 0
    );

    return result;
}


IOReturn
AirportItlwmAWDLInterface::newUserClient(
    task_t owningTask,
    void *securityID,
    UInt type,
    OSDictionary *properties,
    IOUserClient **handler)
{
    airplayLifeProperty(this, "AIRPLAYLifeNewUserClientEnter", 1);

    IOLog(
        "AIRPLAY AWDL LIFE: newUserClient ENTER this=%p type=%u\n",
        this,
        (unsigned int)type
    );

    IOReturn result =
        IO80211VirtualInterface::newUserClient(
            owningTask,
            securityID,
            type,
            properties,
            handler
        );

    IOLog(
        "AIRPLAY AWDL LIFE: newUserClient RETURN=0x%x handler=%p this=%p\n",
        result,
        handler ? *handler : nullptr,
        this
    );

    airplayLifeProperty(
        this,
        "AIRPLAYLifeNewUserClientSuccess",
        result == kIOReturnSuccess ? 1 : 0
    );

    return result;
}


bool
AirportItlwmAWDLInterface::prepareBSDInterface(
    ifnet_t ifp,
    UInt unit)
{
    airplayLifeProperty(this, "AIRPLAYLifePrepareEnter", 1);
    IOLog(
        "AIRPLAY AWDL LIFE: prepareBSDInterface ENTER this=%p ifp=%p unit=%u\n",
        this,
        ifp,
        (unsigned int)unit
    );

    bool result =
        IO80211VirtualInterface::prepareBSDInterface(
            ifp,
            unit
        );

    setProperty(
        "AIRPLAYAWDLBSDIfnetPrepareResult",
        (unsigned long long)(result ? 1 : 0),
        8
    );

    if (ifp != nullptr) {
        gAirplayAWDLBSDIfnet = ifp;

        setProperty(
            "AIRPLAYAWDLBSDIfnetCached",
            (unsigned long long)1,
            8
        );
    }

    IOLog(
        "AIRPLAY AWDL LIFE: prepareBSDInterface RETURN=%d this=%p\n",
        result,
        this
    );

    airplayLifeProperty(
        this,
        "AIRPLAYLifePrepareReturn",
        result ? 1 : 0
    );

    return result;
}


void *
AirportItlwmAWDLInterface::createPeerManager(void)
{
    airplayLifeProperty(this, "AIRPLAYLifePeerEnter", 1);
    IOLog(
        "AIRPLAY AWDL LIFE: createPeerManager ENTER this=%p\n",
        this
    );

    void *result =
        IO80211VirtualInterface::createPeerManager();

    IOLog(
        "AIRPLAY AWDL LIFE: createPeerManager RETURN=%p this=%p\n",
        result,
        this
    );

    airplayLifeProperty(
        this,
        "AIRPLAYLifePeerNonNull",
        result != nullptr ? 1 : 0
    );

    return result;
}


bool
AirportItlwmAWDLInterface::attachToBpf(void)
{
    airplayLifeProperty(this, "AIRPLAYLifeBpfEnter", 1);
    IOLog(
        "AIRPLAY AWDL LIFE: attachToBpf ENTER this=%p\n",
        this
    );

    bool result =
        IO80211VirtualInterface::attachToBpf();

    IOLog(
        "AIRPLAY AWDL LIFE: attachToBpf RETURN=%d this=%p\n",
        result,
        this
    );

    airplayLifeProperty(
        this,
        "AIRPLAYLifeBpfReturn",
        result ? 1 : 0
    );

    return result;
}


bool
AirportItlwmAWDLInterface::configureIfnet(void)
{
    airplayLifeProperty(this, "AIRPLAYLifeIfnetEnter", 1);
    IOLog(
        "AIRPLAY AWDL LIFE: configureIfnet ENTER this=%p\n",
        this
    );

    bool result =
        IO80211VirtualInterface::configureIfnet();

    IOLog(
        "AIRPLAY AWDL LIFE: configureIfnet RETURN=%d this=%p\n",
        result,
        this
    );

    airplayLifeProperty(
        this,
        "AIRPLAYLifeIfnetReturn",
        result ? 1 : 0
    );

    return result;
}


static UInt32 gAirplayAWDLSendPendingHits = 0;
static UInt32 gAirplayAWDLFreePendingHits = 0;
static UInt32 gAirplayAWDLOutputPacketHits = 0;


void
AirportItlwmAWDLInterface::sendPendingPacketsToStack(
    IO80211NetworkPacket **packets,
    UInt count)
{
    UInt32 hits = __atomic_add_fetch(
        &gAirplayAWDLSendPendingHits,
        (UInt32)1,
        __ATOMIC_RELAXED
    );

    setProperty(
        "AIRPLAYAWDLSendPendingHits",
        (unsigned long long)hits,
        32
    );

    setProperty(
        "AIRPLAYAWDLSendPendingLastCount",
        (unsigned long long)count,
        32
    );

    IO80211VirtualInterface::sendPendingPacketsToStack(
        packets,
        count
    );
}


void
AirportItlwmAWDLInterface::freePendingPackets(
    IO80211NetworkPacket **packets,
    UInt count)
{
    UInt32 hits = __atomic_add_fetch(
        &gAirplayAWDLFreePendingHits,
        (UInt32)1,
        __ATOMIC_RELAXED
    );

    setProperty(
        "AIRPLAYAWDLFreePendingHits",
        (unsigned long long)hits,
        32
    );

    setProperty(
        "AIRPLAYAWDLFreePendingLastCount",
        (unsigned long long)count,
        32
    );

    IO80211VirtualInterface::freePendingPackets(
        packets,
        count
    );
}


UInt32
AirportItlwmAWDLInterface::outputPacket(
    mbuf_t packet,
    void *param)
{
    UInt32 hits = __atomic_add_fetch(
        &gAirplayAWDLOutputPacketHits,
        (UInt32)1,
        __ATOMIC_RELAXED
    );

    setProperty(
        "AIRPLAYAWDLOutputPacketHits",
        (unsigned long long)hits,
        32
    );

    /*
     * KGP-style lower-half bridge:
     *
     * Keep Sonoma's native IO80211AWDLProtocol object, but once
     * Apple gives us an mbuf, feed it into AirportItlwm's proven
     * normal transmit path instead of returning it to the V2
     * virtual-interface implementation.
     */
    AirportItlwm *owner =
        OSDynamicCast(AirportItlwm, getProvider());

    setProperty(
        "AIRPLAYAWDLOutputOwnerFound",
        (unsigned long long)(owner != nullptr ? 1 : 0),
        8
    );

    UInt32 result = kIOReturnOutputDropped;

    if (owner != nullptr && packet != nullptr) {
        result = owner->outputPacket(packet, param);
    } else if (packet != nullptr) {
        /*
         * Preserve the old behavior if the provider relationship
         * is unexpectedly unavailable.
         */
        result =
            IO80211VirtualInterface::outputPacket(packet, param);
    }

    setProperty(
        "AIRPLAYAWDLOutputPacketLastResult",
        (unsigned long long)result,
        32
    );

    return result;
}


static UInt32 gAirplayAWDLPendingPacketsZeroHits = 0;
static UInt32 gAirplayAWDLPendingPacketsNonZeroHits = 0;

static UInt32 gAirplayAWDLPendingPacketsAC0Hits = 0;
static UInt32 gAirplayAWDLPendingPacketsAC1Hits = 0;
static UInt32 gAirplayAWDLPendingPacketsAC2Hits = 0;
static UInt32 gAirplayAWDLPendingPacketsAC3Hits = 0;
static UInt32 gAirplayAWDLPendingPacketsACOtherHits = 0;


SInt64
AirportItlwmAWDLInterface::pendingPackets(unsigned char ac)
{
    UInt32 hits = __atomic_add_fetch(
        &gAirplayAWDLPendingPacketsHits,
        (UInt32)1,
        __ATOMIC_RELAXED
    );

    setProperty(
        "AIRPLAYAWDLPendingPacketsHits",
        (unsigned long long)hits,
        32
    );

    setProperty(
        "AIRPLAYAWDLPendingPacketsLastAC",
        (unsigned long long)ac,
        32
    );

    UInt32 acHits = 0;

    switch (ac) {
        case 0:
            acHits = __atomic_add_fetch(
                &gAirplayAWDLPendingPacketsAC0Hits,
                (UInt32)1,
                __ATOMIC_RELAXED
            );
            setProperty(
                "AIRPLAYAWDLPendingPacketsAC0Hits",
                (unsigned long long)acHits,
                32
            );
            break;

        case 1:
            acHits = __atomic_add_fetch(
                &gAirplayAWDLPendingPacketsAC1Hits,
                (UInt32)1,
                __ATOMIC_RELAXED
            );
            setProperty(
                "AIRPLAYAWDLPendingPacketsAC1Hits",
                (unsigned long long)acHits,
                32
            );
            break;

        case 2:
            acHits = __atomic_add_fetch(
                &gAirplayAWDLPendingPacketsAC2Hits,
                (UInt32)1,
                __ATOMIC_RELAXED
            );
            setProperty(
                "AIRPLAYAWDLPendingPacketsAC2Hits",
                (unsigned long long)acHits,
                32
            );
            break;

        case 3:
            acHits = __atomic_add_fetch(
                &gAirplayAWDLPendingPacketsAC3Hits,
                (UInt32)1,
                __ATOMIC_RELAXED
            );
            setProperty(
                "AIRPLAYAWDLPendingPacketsAC3Hits",
                (unsigned long long)acHits,
                32
            );
            break;

        default:
            acHits = __atomic_add_fetch(
                &gAirplayAWDLPendingPacketsACOtherHits,
                (UInt32)1,
                __ATOMIC_RELAXED
            );
            setProperty(
                "AIRPLAYAWDLPendingPacketsACOtherHits",
                (unsigned long long)acHits,
                32
            );
            break;
    }

    SInt64 result =
        IO80211VirtualInterface::pendingPackets(ac);

    /*
     * SONOMA AWDL TX EVENT-SOURCE ARMING EXPERIMENT
     *
     * The native TX submission queue exists and is bound to AWDL,
     * but getWorkLoop() is NULL and its action never fires.
     *
     * Arm only the TX submission queue, and only once, on the
     * controller's already-existing IO80211 workloop.
     */
    static volatile UInt32 txQueueArmAttempted = 0;

    if (gAirplayAWDLNativeTxSubmission != nullptr) {

        setProperty(
            "AIRPLAYNativeTxMethodReadyBefore",
            (unsigned long long)(
                (*reinterpret_cast<bool *>(
                    reinterpret_cast<unsigned char *>(
                        gAirplayAWDLNativeTxSubmission
                    ) + 188
                )) ? 1 : 0
            ),
            8
        );

        AirportItlwm *controller =
            OSDynamicCast(AirportItlwm, getProvider());

        IOWorkLoop *controllerWorkLoop =
            controller != nullptr
            ? controller->getWorkLoop()
            : nullptr;

        setProperty(
            "AIRPLAYNativeTxControllerWorkLoopPresent",
            (unsigned long long)(controllerWorkLoop != nullptr ? 1 : 0),
            8
        );

        if (__sync_bool_compare_and_swap(
                &txQueueArmAttempted,
                (UInt32)0,
                (UInt32)1)) {

            IOReturn armResult = kIOReturnNotReady;

            if (controllerWorkLoop != nullptr) {

                IOWorkLoop *queueWorkLoop =
                    gAirplayAWDLNativeTxSubmission->getWorkLoop();

                if (queueWorkLoop == nullptr) {
                    armResult =
                        controllerWorkLoop->addEventSource(
                            gAirplayAWDLNativeTxSubmission
                        );
                } else {
                    armResult = kIOReturnSuccess;
                }

                if (armResult == kIOReturnSuccess) {
                    gAirplayAWDLNativeTxSubmission->enable();
                }
            }

            setProperty(
                "AIRPLAYNativeTxArmResult",
                (unsigned long long)(UInt32)armResult,
                32
            );
        }

        setProperty(
            "AIRPLAYNativeTxWorkLoopAfterArm",
            (unsigned long long)(
                gAirplayAWDLNativeTxSubmission->getWorkLoop() != nullptr ? 1 : 0
            ),
            8
        );

        setProperty(
            "AIRPLAYNativeTxEnabledAfterArm",
            (unsigned long long)(
                gAirplayAWDLNativeTxSubmission->isEnabled() ? 1 : 0
            ),
            8
        );

        setProperty(
            "AIRPLAYNativeTxMethodReadyAfter",
            (unsigned long long)(
                (*reinterpret_cast<bool *>(
                    reinterpret_cast<unsigned char *>(
                        gAirplayAWDLNativeTxSubmission
                    ) + 188
                )) ? 1 : 0
            ),
            8
        );

        /*
         * TX COMPLETION QUEUE ARM
         *
         * The submission queue required an explicit controller-workloop
         * attachment plus enable() before it became usable.  Apply that
         * same already-proven lifecycle to the native TX completion queue.
         *
         * Do not call requestEnqueue(), completePackets(),
         * packetCompletion(), or bufferCompletion() here.
         */
        if (gAirplayAWDLNativeTxCompletion != nullptr) {

            static volatile UInt32
                txCompletionQueueArmAttempted = 0;

            setProperty(
                "AIRPLAYNativeTxCompWorkLoopBeforeArm",
                (unsigned long long)(
                    gAirplayAWDLNativeTxCompletion->getWorkLoop()
                        != nullptr ? 1 : 0
                ),
                8
            );

            setProperty(
                "AIRPLAYNativeTxCompEnabledBeforeArm",
                (unsigned long long)(
                    gAirplayAWDLNativeTxCompletion->isEnabled()
                        ? 1 : 0
                ),
                8
            );

            setProperty(
                "AIRPLAYNativeTxCompReadyBeforeArm",
                (unsigned long long)(
                    (*reinterpret_cast<bool *>(
                        reinterpret_cast<unsigned char *>(
                            gAirplayAWDLNativeTxCompletion
                        ) + 188
                    )) ? 1 : 0
                ),
                8
            );

            if (__sync_bool_compare_and_swap(
                    &txCompletionQueueArmAttempted,
                    (UInt32)0,
                    (UInt32)1)) {

                IOReturn completionArmResult =
                    kIOReturnNotReady;

                if (controllerWorkLoop != nullptr) {

                    IOWorkLoop *completionWorkLoop =
                        gAirplayAWDLNativeTxCompletion->getWorkLoop();

                    if (completionWorkLoop == nullptr) {
                        completionArmResult =
                            controllerWorkLoop->addEventSource(
                                gAirplayAWDLNativeTxCompletion
                            );
                    } else {
                        completionArmResult =
                            kIOReturnSuccess;
                    }

                    if (completionArmResult ==
                        kIOReturnSuccess) {

                        gAirplayAWDLNativeTxCompletion->enable();
                    }
                }

                setProperty(
                    "AIRPLAYNativeTxCompArmResult",
                    (unsigned long long)(
                        UInt32
                    )completionArmResult,
                    32
                );
            }

            setProperty(
                "AIRPLAYNativeTxCompWorkLoopAfterArm",
                (unsigned long long)(
                    gAirplayAWDLNativeTxCompletion->getWorkLoop()
                        != nullptr ? 1 : 0
                ),
                8
            );

            setProperty(
                "AIRPLAYNativeTxCompEnabledAfterArm",
                (unsigned long long)(
                    gAirplayAWDLNativeTxCompletion->isEnabled()
                        ? 1 : 0
                ),
                8
            );

            setProperty(
                "AIRPLAYNativeTxCompReadyAfterArm",
                (unsigned long long)(
                    (*reinterpret_cast<bool *>(
                        reinterpret_cast<unsigned char *>(
                            gAirplayAWDLNativeTxCompletion
                        ) + 188
                    )) ? 1 : 0
                ),
                8
            );


        }
    }

    /*
     * BCM/Skywalk TX dequeue experiment.
     *
     * IOSkywalkTxSubmissionQueue::requestDequeue(..., 1)
     * advances the dequeue generation and schedules the queue's
     * asynchronous work path.  Keep this deliberately bounded.
     */
    static volatile UInt32 txDequeueAttempts = 0;
    static volatile UInt32 txDequeueSuccesses = 0;
    static volatile UInt32 txDequeueFailures = 0;

    UInt32 attempt =
        __atomic_load_n(
            &txDequeueAttempts,
            __ATOMIC_RELAXED
        );

    if (result == 0 &&
        gAirplayAWDLNativeTxSubmission != nullptr &&
        attempt < 16) {

        attempt =
            __atomic_add_fetch(
                &txDequeueAttempts,
                (UInt32)1,
                __ATOMIC_RELAXED
            );

        IOReturn dequeueResult =
            gAirplayAWDLNativeTxSubmission->requestDequeue(
                nullptr,
                1
            );

        setProperty(
            "AIRPLAYTxRequestDequeueAttempts",
            (unsigned long long)attempt,
            32
        );

        setProperty(
            "AIRPLAYTxRequestDequeueLastAC",
            (unsigned long long)ac,
            32
        );

        setProperty(
            "AIRPLAYTxRequestDequeueLastResult",
            (unsigned long long)(UInt32)dequeueResult,
            32
        );

        if (dequeueResult == kIOReturnSuccess) {
            UInt32 successes =
                __atomic_add_fetch(
                    &txDequeueSuccesses,
                    (UInt32)1,
                    __ATOMIC_RELAXED
                );

            setProperty(
                "AIRPLAYTxRequestDequeueSuccesses",
                (unsigned long long)successes,
                32
            );
        } else {
            UInt32 failures =
                __atomic_add_fetch(
                    &txDequeueFailures,
                    (UInt32)1,
                    __ATOMIC_RELAXED
                );

            setProperty(
                "AIRPLAYTxRequestDequeueFailures",
                (unsigned long long)failures,
                32
            );
        }
    }

    UInt32 nativeTxCount = 0;
    UInt32 nativeTxBytes = 0;
    IOReturn nativeTxBytesResult = kIOReturnNotReady;

    if (gAirplayAWDLNativeTxSubmission != nullptr) {
        nativeTxCount =
            gAirplayAWDLNativeTxSubmission->getPacketCount();

        nativeTxBytesResult =
            gAirplayAWDLNativeTxSubmission->getDataByteCount(
                &nativeTxBytes
            );
    }

    /*
     * Read-only native queue lifecycle snapshot.
     * Offsets are from the exact Sonoma IOSkywalk binary.
     * No private methods are called and no queue state is modified.
     */
    void *nativeTxWorkLoop = nullptr;
    void *nativeTxKernNetifQueue = nullptr;
    void *nativeTxQueueSet = nullptr;
    void *nativeTxBSDClientInfo = nullptr;
    UInt8 nativeTxQueueReadyRaw = 0;
    UInt32 nativeTxBSDClientDword = 0;
    UInt8 nativeTxBSDClientFlag = 0;

    if (gAirplayAWDLNativeTxSubmission != nullptr) {
        const UInt8 *qraw =
            reinterpret_cast<const UInt8 *>(
                gAirplayAWDLNativeTxSubmission
            );

        __builtin_memcpy(
            &nativeTxWorkLoop,
            qraw + 0x30,
            sizeof(nativeTxWorkLoop)
        );

        __builtin_memcpy(
            &nativeTxKernNetifQueue,
            qraw + 0x78,
            sizeof(nativeTxKernNetifQueue)
        );

        __builtin_memcpy(
            &nativeTxQueueSet,
            qraw + 0x80,
            sizeof(nativeTxQueueSet)
        );

        __builtin_memcpy(
            &nativeTxQueueReadyRaw,
            qraw + 0xcc,
            sizeof(nativeTxQueueReadyRaw)
        );

        __builtin_memcpy(
            &nativeTxBSDClientInfo,
            qraw + 0xf8,
            sizeof(nativeTxBSDClientInfo)
        );

        __builtin_memcpy(
            &nativeTxBSDClientDword,
            qraw + 0x144,
            sizeof(nativeTxBSDClientDword)
        );

        __builtin_memcpy(
            &nativeTxBSDClientFlag,
            qraw + 0x164,
            sizeof(nativeTxBSDClientFlag)
        );
    }

    setProperty(
        "AIRPLAYNativeTxWorkLoopPresent",
        (unsigned long long)(
            nativeTxWorkLoop != nullptr ? 1 : 0
        ),
        8
    );

    setProperty(
        "AIRPLAYNativeTxKernNetifQueuePresent",
        (unsigned long long)(
            nativeTxKernNetifQueue != nullptr ? 1 : 0
        ),
        8
    );

    setProperty(
        "AIRPLAYNativeTxQueueSetPresent",
        (unsigned long long)(
            nativeTxQueueSet != nullptr ? 1 : 0
        ),
        8
    );

    setProperty(
        "AIRPLAYNativeTxQueueReadyRaw",
        (unsigned long long)(
            nativeTxQueueReadyRaw != 0 ? 1 : 0
        ),
        8
    );

    setProperty(
        "AIRPLAYNativeTxBSDClientInfoPresent",
        (unsigned long long)(
            nativeTxBSDClientInfo != nullptr ? 1 : 0
        ),
        8
    );

    setProperty(
        "AIRPLAYNativeTxBSDClientDword",
        (unsigned long long)nativeTxBSDClientDword,
        32
    );

    setProperty(
        "AIRPLAYNativeTxBSDClientFlag",
        (unsigned long long)nativeTxBSDClientFlag,
        8
    );

    setProperty(
        "AIRPLAYNativeTxQueuePacketCount",
        (unsigned long long)nativeTxCount,
        32
    );

    setProperty(
        "AIRPLAYNativeTxQueueByteCount",
        (unsigned long long)nativeTxBytes,
        32
    );

    setProperty(
        "AIRPLAYNativeTxQueueByteCountResult",
        (unsigned long long)(UInt32)nativeTxBytesResult,
        32
    );

    setProperty(
        "AIRPLAYNativeTxQueuePresent",
        (unsigned long long)(
            gAirplayAWDLNativeTxSubmission != nullptr ? 1 : 0
        ),
        8
    );

    if (result == 0) {
        UInt32 zeroHits = __atomic_add_fetch(
            &gAirplayAWDLPendingPacketsZeroHits,
            (UInt32)1,
            __ATOMIC_RELAXED
        );

        setProperty(
            "AIRPLAYAWDLPendingPacketsZeroHits",
            (unsigned long long)zeroHits,
            32
        );
    } else {
        UInt32 nonZeroHits = __atomic_add_fetch(
            &gAirplayAWDLPendingPacketsNonZeroHits,
            (UInt32)1,
            __ATOMIC_RELAXED
        );

        setProperty(
            "AIRPLAYAWDLPendingPacketsNonZeroHits",
            (unsigned long long)nonZeroHits,
            32
        );

        setProperty(
            "AIRPLAYAWDLPendingPacketsNonZeroLastRaw",
            (unsigned long long)result,
            64
        );

        setProperty(
            "AIRPLAYAWDLPendingPacketsNonZeroLastNegative",
            result < 0 ? 1 : 0,
            32
        );
    }

    setProperty(
        "AIRPLAYAWDLPendingPacketsLastResult",
        (unsigned long long)result,
        64
    );

    return result;
}


SInt64
AirportItlwmAWDLInterface::packetSpace(unsigned char ac)
{
    UInt32 hits = __atomic_add_fetch(
        &gAirplayAWDLPacketSpaceHits,
        (UInt32)1,
        __ATOMIC_RELAXED
    );

    setProperty(
        "AIRPLAYAWDLPacketSpaceHits",
        (unsigned long long)hits,
        32
    );

    setProperty(
        "AIRPLAYAWDLPacketSpaceLastAC",
        (unsigned long long)ac,
        32
    );

    SInt64 result =
        IO80211VirtualInterface::packetSpace(ac);

    setProperty(
        "AIRPLAYAWDLPacketSpaceLastResult",
        (unsigned long long)result,
        64
    );

    return result;
}



void
AirportItlwmAWDLInterface::forwardPacket(
    IO80211NetworkPacket *packet)
{
    static UInt32 hits = 0;

    UInt32 value = __atomic_add_fetch(
        &hits,
        (UInt32)1,
        __ATOMIC_RELAXED
    );

    setProperty(
        "AIRPLAYAWDLForwardPacketHits",
        (unsigned long long)value,
        32
    );

    setProperty(
        "AIRPLAYAWDLForwardPacketNonNull",
        (unsigned long long)(packet != nullptr ? 1 : 0),
        8
    );

    IO80211VirtualInterface::forwardPacket(packet);
}



UInt32
AirportItlwmAWDLInterface::configureAQMOutput(void)
{
    static UInt32 hits = 0;

    UInt32 value = __atomic_add_fetch(
        &hits,
        (UInt32)1,
        __ATOMIC_RELAXED
    );

    setProperty(
        "AIRPLAYAWDLConfigureAQMHits",
        (unsigned long long)value,
        32
    );

    UInt32 result =
        IO80211VirtualInterface::configureAQMOutput();

    setProperty(
        "AIRPLAYAWDLConfigureAQMLastResult",
        (unsigned long long)result,
        32
    );

    return result;
}

void
AirportItlwmAWDLInterface::dupAndTransmitMcastPacket(
    IO80211NetworkPacket *packet,
    unsigned char *a,
    unsigned char *b)
{
    static UInt32 hits = 0;

    UInt32 value = __atomic_add_fetch(
        &hits,
        (UInt32)1,
        __ATOMIC_RELAXED
    );

    setProperty(
        "AIRPLAYAWDLDupMcastHits",
        (unsigned long long)value,
        32
    );

    setProperty(
        "AIRPLAYAWDLDupMcastNonNull",
        (unsigned long long)(packet != nullptr ? 1 : 0),
        8
    );

    IO80211VirtualInterface::dupAndTransmitMcastPacket(
        packet,
        a,
        b
    );
}


void
AirportItlwmAWDLInterface::freeMulticastPacket(
    IO80211NetworkPacket *packet)
{
    static UInt32 hits = 0;

    UInt32 value = __atomic_add_fetch(
        &hits,
        (UInt32)1,
        __ATOMIC_RELAXED
    );

    setProperty(
        "AIRPLAYAWDLFreeMcastHits",
        (unsigned long long)value,
        32
    );

    IO80211VirtualInterface::freeMulticastPacket(packet);
}


void
AirportItlwmAWDLInterface::triggerAWDLMulticastTx(
    UInt arg,
    unsigned char ac)
{
    UInt32 hits = __atomic_add_fetch(
        &gAirplayAWDLTriggerMcastHits,
        (UInt32)1,
        __ATOMIC_RELAXED
    );

    setProperty(
        "AIRPLAYAWDLTriggerMcastHits",
        (unsigned long long)hits,
        32
    );

    setProperty(
        "AIRPLAYAWDLTriggerMcastArg",
        (unsigned long long)arg,
        32
    );

    setProperty(
        "AIRPLAYAWDLTriggerMcastAC",
        (unsigned long long)ac,
        32
    );

    IO80211VirtualInterface::triggerAWDLMulticastTx(arg, ac);
}


void
AirportItlwmAWDLInterface::p2pMulticastTx(
    IO80211NetworkPacket **packets,
    UInt count)
{
    UInt32 hits = __atomic_add_fetch(
        &gAirplayAWDLP2PMcastHits,
        (UInt32)1,
        __ATOMIC_RELAXED
    );

    setProperty(
        "AIRPLAYAWDLP2PMcastHits",
        (unsigned long long)hits,
        32
    );

    setProperty(
        "AIRPLAYAWDLP2PMcastCount",
        (unsigned long long)count,
        32
    );

    IO80211VirtualInterface::p2pMulticastTx(packets, count);
}



/*
 * AIRPLAYV2TxAccessor
 *
 * Diagnostic-only probes for the inherited Sonoma V2 TX infrastructure.
 * Do not alter queue ownership or packet contents.
 */

static UInt32 gAirplayV2GetTxQueueDepthHits = 0;
static UInt32 gAirplayV2GetTxSubQueueHits = 0;
static UInt32 gAirplayV2GetTxPacketPoolHits = 0;
static UInt32 gAirplayV2NotifyQueueStateHits = 0;

UInt64
AirportItlwmAWDLInterface::getTxQueueDepth(void)
{
    UInt32 hits = __atomic_add_fetch(
        &gAirplayV2GetTxQueueDepthHits,
        (UInt32)1,
        __ATOMIC_RELAXED
    );

    UInt64 result =
        IO80211SkywalkInterface::getTxQueueDepth();

    setProperty(
        "AIRPLAYV2GetTxQueueDepthHits",
        (unsigned long long)hits,
        32
    );

    setProperty(
        "AIRPLAYV2GetTxQueueDepthLastResult",
        (unsigned long long)result,
        64
    );

    return result;
}

void *
AirportItlwmAWDLInterface::getTxPacketPool(void)
{
    UInt32 hits = __atomic_add_fetch(
        &gAirplayV2GetTxPacketPoolHits,
        (UInt32)1,
        __ATOMIC_RELAXED
    );

    void *pool =
        gAirplayAWDLNativePool != nullptr
        ? (void *)gAirplayAWDLNativePool
        : IO80211SkywalkInterface::getTxPacketPool();

    /* NOMONITOR: stock pool only for the setInterfaceEnable() -> allocBpfResources() caller. */
    if (gAirplayBpfEnableThread != nullptr &&
        gAirplayBpfEnableThread == current_thread()) {
        pool = IO80211SkywalkInterface::getTxPacketPool();
        gAirplayBpfGuardSuppressed++;
    }

    setProperty(
        "AIRPLAYV2GetTxPacketPoolHits",
        (unsigned long long)hits,
        32
    );

    setProperty(
        "AIRPLAYV2GetTxPacketPoolNonNull",
        (unsigned long long)(pool != nullptr ? 1 : 0),
        8
    );

    setProperty(
        "AIRPLAYV2GetTxPacketPoolNative",
        (unsigned long long)(
            pool == (void *)gAirplayAWDLNativePool &&
            pool != nullptr ? 1 : 0
        ),
        8
    );

    return pool;
}

extern "C" void *
_ZN25AirportItlwmAWDLInterface13getTxSubQueueE17apple80211_wme_ac(
    AirportItlwmAWDLInterface *self,
    unsigned long long opaqueAc)
{
    (void)opaqueAc;

    UInt32 hits = __atomic_add_fetch(
        &gAirplayV2GetTxSubQueueHits,
        (UInt32)1,
        __ATOMIC_RELAXED
    );

    void *queue =
        gAirplayAWDLNativeTxSubmission != nullptr
        ? (void *)gAirplayAWDLNativeTxSubmission
        : nullptr;

    if (self != nullptr) {
        self->setProperty(
            "AIRPLAYV2GetTxSubQueueShimHits",
            (unsigned long long)hits,
            32
        );

        self->setProperty(
            "AIRPLAYV2GetTxSubQueueShimNonNull",
            (unsigned long long)(queue != nullptr ? 1 : 0),
            8
        );
    }

    return queue;
}

void *
AirportItlwmAWDLInterface::getTxCompQueue(void)
{
    void *queue =
        gAirplayAWDLNativeTxCompletion != nullptr
        ? (void *)gAirplayAWDLNativeTxCompletion
        : IO80211SkywalkInterface::getTxCompQueue();

    setProperty(
        "AIRPLAYV2GetTxCompQueueNonNull",
        (unsigned long long)(queue != nullptr ? 1 : 0),
        8
    );

    return queue;
}

void *
AirportItlwmAWDLInterface::getRxCompQueue(void)
{
    void *queue =
        gAirplayAWDLNativeRxCompletion != nullptr
        ? (void *)gAirplayAWDLNativeRxCompletion
        : IO80211SkywalkInterface::getRxCompQueue();

    setProperty(
        "AIRPLAYV2GetRxCompQueueNonNull",
        (unsigned long long)(queue != nullptr ? 1 : 0),
        8
    );

    return queue;
}

void *
AirportItlwmAWDLInterface::getRxPacketPool(void)
{
    void *pool =
        gAirplayAWDLNativePool != nullptr
        ? (void *)gAirplayAWDLNativePool
        : IO80211SkywalkInterface::getRxPacketPool();

    setProperty(
        "AIRPLAYV2GetRxPacketPoolNonNull",
        (unsigned long long)(pool != nullptr ? 1 : 0),
        8
    );

    return pool;
}

int
AirportItlwmAWDLInterface::getNumTxQueues(void)
{
    int result =
        gAirplayAWDLNativeTxSubmission != nullptr
        ? 1
        : IO80211SkywalkInterface::getNumTxQueues();

    setProperty(
        "AIRPLAYV2GetNumTxQueuesLastResult",
        (unsigned long long)result,
        32
    );

    return result;
}

IOReturn
AirportItlwmAWDLInterface::getSSID(apple80211_ssid_data *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::getCHANNEL(apple80211_channel_data *)
{
    IOLog("AIRPLAY AWDL API: getCHANNEL\n");
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::getBSSID(apple80211_bssid_data *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::getSTATE(apple80211_state_data *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::getAWDL_SYNC_PARAMS(apple80211_awdl_sync_params *)
{
    IOLog("AIRPLAY AWDL API: getAWDL_SYNC_PARAMS\n");
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::getAWDL_SYNC_ENABLED(
    apple80211_awdl_sync_enabled *data)
{
    airplayLifeProperty(this, "AIRPLAYGetSyncEnabledEnter", 1);

    if (data == nullptr) {
        airplayLifeProperty(this, "AIRPLAYGetSyncEnabledDataNonNull", 0);
        return kIOReturnBadArgument;
    }

    airplayLifeProperty(this, "AIRPLAYGetSyncEnabledDataNonNull", 1);

    AirportItlwm *owner =
        OSDynamicCast(AirportItlwm, getProvider());

    airplayLifeProperty(
        this,
        "AIRPLAYGetSyncEnabledOwnerNonNull",
        owner != nullptr ? 1 : 0
    );

    if (owner == nullptr) {
        IOLog("AIRPLAY AWDL SYNC_ENABLED GET: no AirportItlwm owner\n");
        return kIOReturnError;
    }

    data->version = APPLE80211_VERSION;
    data->unk1 = 0;
    data->enabled = owner->awdlSyncEnable ? 1 : 0;

    airplayLifeProperty(
        this,
        "AIRPLAYGetSyncEnabledValue",
        data->enabled ? 1 : 0
    );

    IOLog(
        "AIRPLAY AWDL SYNC_ENABLED GET: enabled=%u\n",
        data->enabled ? 1U : 0U
    );

    return kIOReturnSuccess;
}

IOReturn
AirportItlwmAWDLInterface::getAWDL_EXTENSION_STATE_MACHINE_PARAMETERS(apple80211_awdl_extension_state_machine_parameter *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::getAWDL_ELECTION_ID(apple80211_awdl_election_id *)
{
    IOLog("AIRPLAY AWDL API: getAWDL_ELECTION_ID\n");
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::getAWDL_ELECTION_METRIC(apple80211_awdl_election_metric *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::getAWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE(
    apple80211_awdl_sync_channel_sequence *data)
{
    airplayLifeProperty(this, "AIRPLAYGetChannelSequenceEnter", 1);

    if (data == nullptr) {
        airplayLifeProperty(this, "AIRPLAYGetChannelSequenceDataNonNull", 0);
        return kIOReturnBadArgument;
    }

    airplayLifeProperty(this, "AIRPLAYGetChannelSequenceDataNonNull", 1);

    data->version = APPLE80211_VERSION;

    IOLog("AIRPLAY AWDL CHANNEL_SEQUENCE GET: success\n");

    return kIOReturnSuccess;
}

IOReturn
AirportItlwmAWDLInterface::getPEER_CACHE_MAXIMUM_SIZE(apple80211_peer_cache_maximum_size *data)
{
    AirportItlwm *owner = OSDynamicCast(AirportItlwm, getProvider());
    if (owner) owner->peerCacheObserve(false, data);
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::getAWDL_MASTER_CHANNEL(apple80211_awdl_master_channel *)
{
    IOLog("AIRPLAY AWDL API: getAWDL_MASTER_CHANNEL\n");
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::getAWDL_SYNC_STATE(apple80211_awdl_sync_state *)
{
    IOLog("AIRPLAY AWDL API: getAWDL_SYNC_STATE\n");
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::getAWDL_ELECTION_RSSI_THRESHOLDS(apple80211_awdl_election_rssi_thresholds *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::getAWDL_PRESENCE_MODE(apple80211_awdl_presence_mode *)
{
    IOLog("AIRPLAY AWDL API: getAWDL_PRESENCE_MODE\n");
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::getAWDL_ELECTION_PARAMS(apple80211_awdl_election_params *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::getAWDL_DEVICE_CAPABILITIES(apple80211_awdl_device_capabilities *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::getAWDL_SECONDARY_MASTER_CHANNEL(apple80211_awdl_secondary_master_channel *)
{
    IOLog("AIRPLAY AWDL API: getAWDL_SECONDARY_MASTER_CHANNEL\n");
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::getAWDL_AF_TX_MODE(apple80211_awdl_af_tx_mode *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::getAWDL_MIN_RATE(apple80211_awdl_min_rate *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::getAWDL_ENCRYPTION_TYPE(apple80211_encrypt *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::getAWDL_TXCAL_PERIOD(apple80211_awdl_txcal_period *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::getAWDL_DEV_STATS(apple80211_awdl_dev_stats *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::getAWDL_DFSP_CONFIG(apple80211_awdl_dfsp_config *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::getAWDL_CCA(apple80211_awdl_cca *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::getAWDL_AF_SECONDARY_PAYLOAD_CAPABILITIES(
    apple80211_awdl_cap *data)
{
    airplayLifeProperty(this, "AIRPLAYGetAFSecondaryCapEnter", 1);

    if (data == nullptr)
        return kIOReturnBadArgument;

    data->cap = 0;

    airplayLifeProperty(this, "AIRPLAYGetAFSecondaryCapSuccess", 1);

    IOLog(
        "AIRPLAY AWDL CAP: AF_SECONDARY_PAYLOAD_CAPABILITIES success cap=%u\n",
        (unsigned int)data->cap
    );

    return kIOReturnSuccess;
}

IOReturn
AirportItlwmAWDLInterface::getLLW_PARAMS(apple80211_llw_params *data)
{
    airplayLifeProperty(
        this,
        "AIRPLAYGetLLWParamsEnter",
        1
    );

    airplayLifeProperty(
        this,
        "AIRPLAYGetLLWParamsNonNull",
        data != nullptr ? 1 : 0
    );

    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::setSSID(apple80211_ssid_data *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::setCHANNEL(apple80211_channel_data *)
{
    IOLog("AIRPLAY AWDL API: setCHANNEL\n");
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_SYNC_PARAMS(apple80211_awdl_sync_params *data)
{
    airplayLifeProperty(this, "AIRPLAYSetSyncParamsEnter", 1);

    if (data == nullptr) {
        airplayLifeProperty(this, "AIRPLAYSetSyncParamsDataNonNull", 0);
        return kIOReturnBadArgument;
    }

    airplayLifeProperty(this, "AIRPLAYSetSyncParamsDataNonNull", 1);

    this->setProperty(
        "AIRPLAYSyncParamsVersion",
        (unsigned long long)data->version,
        32
    );

    this->setProperty(
        "AIRPLAYSyncParamsAWLength",
        (unsigned long long)data->availability_window_length,
        32
    );

    this->setProperty(
        "AIRPLAYSyncParamsAWPeriod",
        (unsigned long long)data->availability_window_period,
        32
    );

    this->setProperty(
        "AIRPLAYSyncParamsExtensionLength",
        (unsigned long long)data->extension_length,
        32
    );

    this->setProperty(
        "AIRPLAYSyncParamsSyncFramePeriod",
        (unsigned long long)data->synchronization_frame_period,
        32
    );

    /* PSFTX-20261015: keep the values for the PSF sync-params TLV */
    if (data->availability_window_length != 0)
        gAirplayPsfAWLength = (UInt16)data->availability_window_length;
    if (data->availability_window_period != 0)
        gAirplayPsfAWPeriod = (UInt16)data->availability_window_period;
    if (data->extension_length != 0)
        gAirplayPsfExtLength = (UInt16)data->extension_length;
    if (data->synchronization_frame_period != 0)
        gAirplayPsfSyncFramePeriod = (UInt16)data->synchronization_frame_period;
    IOLog("AIRPLAY AWDL SYNC_PARAMS: accepted configuration request\n");

    return kIOReturnSuccess;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_SYNC_ENABLED(
    apple80211_awdl_sync_enabled *data)
{
    airplayLifeProperty(this, "AIRPLAYSync117Enter", 1);

    if (data == nullptr) {
        airplayLifeProperty(this, "AIRPLAYSync117DataNonNull", 0);
        return kIOReturnBadArgument;
    }

    airplayLifeProperty(this, "AIRPLAYSync117DataNonNull", 1);

    AirportItlwm *owner =
        OSDynamicCast(AirportItlwm, getProvider());

    airplayLifeProperty(
        this,
        "AIRPLAYSync117OwnerNonNull",
        owner != nullptr ? 1 : 0
    );

    if (owner == nullptr) {
        IOLog("AIRPLAY AWDL SYNC_ENABLED SET: no AirportItlwm owner\n");
        return kIOReturnError;
    }

    owner->awdlSyncEnable = data->enabled != 0;
    airplayAwdlSetSyncActive(owner->awdlSyncEnable); /* P2PGATE */

    /* SCHEDARM: how often macOS armed / disarmed the AWDL schedule this boot */
    static UInt32 schedarmSyncOn = 0, schedarmSyncOff = 0;
    if (owner->awdlSyncEnable) schedarmSyncOn++; else schedarmSyncOff++;
    setProperty("AIRPLAYSyncSetOnCount", (unsigned long long)schedarmSyncOn, 32);
    setProperty("AIRPLAYSyncSetOffCount", (unsigned long long)schedarmSyncOff, 32);

    gAirplayAWDLScheduleCache.armed =
        owner->awdlSyncEnable ? 1 : 0;

    setProperty(
        "AIRPLAYScheduleArmed",
        (unsigned long long)
            gAirplayAWDLScheduleCache.armed,
        8
    );

    setProperty(
        "AIRPLAYScheduleReady",
        (unsigned long long)(
            gAirplayAWDLScheduleCache.valid &&
            gAirplayAWDLScheduleCache.armed
                ? 1 : 0
        ),
        8
    );


    airplayLifeProperty(
        this,
        "AIRPLAYSync117Enabled",
        owner->awdlSyncEnable ? 1 : 0
    );

    IOLog(
        "AIRPLAY AWDL SYNC_ENABLED SET: enabled=%u\n",
        owner->awdlSyncEnable ? 1U : 0U
    );

    return kIOReturnSuccess;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_EXTENSION_STATE_MACHINE_PARAMETERS(
    apple80211_awdl_extension_state_machine_parameter *data)
{
    airplayLifeProperty(this, "AIRPLAYExtensionStateEnter", 1);

    if (data == nullptr) {
        airplayLifeProperty(this, "AIRPLAYExtensionStateDataNonNull", 0);
        return kIOReturnBadArgument;
    }

    airplayLifeProperty(this, "AIRPLAYExtensionStateDataNonNull", 1);

    IOLog(
        "AIRPLAY AWDL EXTENSION_STATE: unk1=%u unk2=%u unk3=%u unk4=%u\n",
        (unsigned int)data->unk1,
        (unsigned int)data->unk2,
        (unsigned int)data->unk3,
        (unsigned int)data->unk4
    );

    airplayLifeProperty(this, "AIRPLAYExtensionStateSuccess", 1);

    return kIOReturnSuccess;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_ELECTION_ID(apple80211_awdl_election_id *data)
{
    airplayLifeProperty(this, "AIRPLAYSetElectionIDEnter", 1);

    if (data == nullptr) {
        airplayLifeProperty(this, "AIRPLAYSetElectionIDDataNonNull", 0);
        return kIOReturnBadArgument;
    }

    airplayLifeProperty(this, "AIRPLAYSetElectionIDDataNonNull", 1);

    this->setProperty(
        "AIRPLAYElectionIDValue",
        (unsigned long long)data->election_id,
        32
    );

    IOLog("AIRPLAY AWDL ELECTION_ID: accepted configuration request\n");

    return kIOReturnSuccess;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_BSSID(apple80211_awdl_bssid *data)
{
    airplayLifeProperty(this, "AIRPLAYSetBSSIDEnter", 1);

    if (data == nullptr) {
        airplayLifeProperty(this, "AIRPLAYSetBSSIDDataNonNull", 0);
        return kIOReturnBadArgument;
    }

    airplayLifeProperty(this, "AIRPLAYSetBSSIDDataNonNull", 1);

    IOLog("AIRPLAY AWDL BSSID: accepted configuration request\n");

    return kIOReturnSuccess;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_ELECTION_METRIC(
    apple80211_awdl_election_metric *data)
{
    airplayLifeProperty(this, "AIRPLAYElectionMetricEnter", 1);

    if (data == nullptr) {
        airplayLifeProperty(this, "AIRPLAYElectionMetricDataNonNull", 0);
        return kIOReturnBadArgument;
    }

    airplayLifeProperty(this, "AIRPLAYElectionMetricDataNonNull", 1);

    IOLog(
        "AIRPLAY AWDL ELECTION_METRIC: metric=%u\n",
        (unsigned int)data->metric
    );

    airplayLifeProperty(this, "AIRPLAYElectionMetricSuccess", 1);

    return kIOReturnSuccess;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE(
    apple80211_awdl_sync_channel_sequence *data)
{
    airplayLifeProperty(this, "AIRPLAYSetChannelSequenceEnter", 1);

    if (data == nullptr) {
        airplayLifeProperty(this, "AIRPLAYSetChannelSequenceDataNonNull", 0);
        return kIOReturnBadArgument;
    }

    airplayLifeProperty(this, "AIRPLAYSetChannelSequenceDataNonNull", 1);

    this->setProperty(
        "AIRPLAYChannelSequenceVersion",
        (unsigned long long)data->version,
        32
    );

    this->setProperty(
        "AIRPLAYChannelSequenceLength",
        (unsigned long long)data->length,
        32
    );

    this->setProperty(
        "AIRPLAYChannelSequenceEncoding",
        (unsigned long long)data->encoding,
        32
    );

    this->setProperty(
        "AIRPLAYChannelSequenceStepCount",
        (unsigned long long)data->step_count,
        32
    );

    this->setProperty(
        "AIRPLAYChannelSequenceDuplicateCount",
        (unsigned long long)data->duplicate_count,
        32
    );

    this->setProperty(
        "AIRPLAYChannelSequenceFillChannel",
        (unsigned long long)data->fill_channel,
        32
    );

    OSData *airplayChannelSequenceRaw =
        OSData::withBytes(data, sizeof(*data));

    if (airplayChannelSequenceRaw != nullptr) {
        this->setProperty(
            "AIRPLAYChannelSequenceRaw",
            airplayChannelSequenceRaw
        );
        airplayChannelSequenceRaw->release();
    }

    IOLog(
        "AIRPLAY AWDL CHANNEL_SEQUENCE: length=%u step=%u duplicate=%u fill=%d encoding=%u\n",
        data->length,
        data->step_count,
        data->duplicate_count,
        data->fill_channel,
        data->encoding
    );

    airplayCacheSonomaSchedule(this, data);

    /*
     * AIRPLAY:
     * Compare Apple's parsed schedule with the previous callback.
     *
     * The cache generation itself cannot be used because it increments
     * on every callback, including identical schedules.
     */
    static bool havePreviousSchedule = false;
    static AirplayAWDLScheduleCache previousSchedule = {};

    bool scheduleChanged =
        !havePreviousSchedule ||
        previousSchedule.valid !=
            gAirplayAWDLScheduleCache.valid ||
        previousSchedule.version !=
            gAirplayAWDLScheduleCache.version ||
        previousSchedule.length !=
            gAirplayAWDLScheduleCache.length ||
        previousSchedule.encoding !=
            gAirplayAWDLScheduleCache.encoding ||
        previousSchedule.stepCount !=
            gAirplayAWDLScheduleCache.stepCount ||
        previousSchedule.duplicateCount !=
            gAirplayAWDLScheduleCache.duplicateCount ||
        previousSchedule.fillChannel !=
            gAirplayAWDLScheduleCache.fillChannel;

    for (unsigned int i = 0; i < 16; i++) {
        if (previousSchedule.channels[i] !=
                gAirplayAWDLScheduleCache.channels[i] ||
            previousSchedule.flags[i] !=
                gAirplayAWDLScheduleCache.flags[i]) {
            scheduleChanged = true;
        }
    }

    previousSchedule =
        gAirplayAWDLScheduleCache;

    havePreviousSchedule = true;

    this->setProperty(
        "AIRPLAYScheduleChanged",
        (unsigned long long)(
            scheduleChanged ? 1 : 0
        ),
        8
    );

    if (scheduleChanged &&
        gAirplayAWDLScheduleCache.valid) {

        AirportItlwm *owner =
            OSDynamicCast(
                AirportItlwm,
                getProvider()
            );

        ItlIwx *iwx = nullptr;

        if (owner != nullptr &&
            owner->fHalService != nullptr) {

            iwx =
                OSDynamicCast(
                    ItlIwx,
                    owner->fHalService
                );
        }

        this->setProperty(
            "AIRPLAYIWXP2PScheduleOwnerFound",
            (unsigned long long)(
                owner != nullptr ? 1 : 0
            ),
            8
        );

        this->setProperty(
            "AIRPLAYIWXP2PScheduleIwxFound",
            (unsigned long long)(
                iwx != nullptr ? 1 : 0
            ),
            8
        );

        bool queued = false;

        if (iwx != nullptr) {
            /*
             * SCHEDARM: push Apple's channel schedule to the firmware again.
             * iwx_airplay_queue_p2p_session() returns false at once unless
             * boot-arg -awdlexp is set, so a normal boot is unchanged.
             */
            queued = iwx->iwx_airplay_queue_p2p_session();

            this->setProperty(
                "AIRPLAYIWXP2PManualScheduleTriggerSuppressed",
                (unsigned long long)(
                    airplayAwdlExperimentsEnabled() ? 0 : 1
                ),
                8
            );
        }

        this->setProperty(
            "AIRPLAYIWXP2PScheduleQueued",
            (unsigned long long)(
                queued ? 1 : 0
            ),
            8
        );
    }

    return kIOReturnSuccess;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_MASTER_CHANNEL(apple80211_awdl_master_channel *data)
{
    airplayLifeProperty(this, "AIRPLAYSetMasterChannelEnter", 1);

    if (data == nullptr) {
        airplayLifeProperty(this, "AIRPLAYSetMasterChannelDataNonNull", 0);
        return kIOReturnBadArgument;
    }

    airplayLifeProperty(this, "AIRPLAYSetMasterChannelDataNonNull", 1);

    this->setProperty(
        "AIRPLAYMasterChannelValue",
        (unsigned long long)data->master_channel,
        32
    );

    gAirplayPsfMasterChannel = (UInt8)data->master_channel; /* PSFTX-20261015 */
    IOLog("AIRPLAY AWDL MASTER_CHANNEL: accepted configuration request\n");

    return kIOReturnSuccess;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_SYNC_STATE(apple80211_awdl_sync_state *data)
{
    airplayLifeProperty(this, "AIRPLAYSetSyncStateEnter", 1);

    if (data == nullptr) {
        airplayLifeProperty(this, "AIRPLAYSetSyncStateDataNonNull", 0);
        return kIOReturnBadArgument;
    }

    airplayLifeProperty(this, "AIRPLAYSetSyncStateDataNonNull", 1);

    this->setProperty(
        "AIRPLAYSyncStateValue",
        (unsigned long long)data->state,
        32
    );

    IOLog("AIRPLAY AWDL SYNC_STATE: accepted configuration request\n");

    return kIOReturnSuccess;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_ELECTION_RSSI_THRESHOLDS(apple80211_awdl_election_rssi_thresholds *data)
{
    airplayLifeProperty(this, "AIRPLAYSetRSSIThresholdsEnter", 1);

    if (data == nullptr) {
        airplayLifeProperty(this, "AIRPLAYSetRSSIThresholdsDataNonNull", 0);
        return kIOReturnBadArgument;
    }

    airplayLifeProperty(this, "AIRPLAYSetRSSIThresholdsDataNonNull", 1);

    IOLog("AIRPLAY AWDL RSSI_THRESHOLDS: accepted configuration request\n");

    return kIOReturnSuccess;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_PRESENCE_MODE(
    apple80211_awdl_presence_mode *data)
{
    airplayLifeProperty(this, "AIRPLAYPresenceModeEnter", 1);

    if (data == nullptr) {
        airplayLifeProperty(this, "AIRPLAYPresenceModeDataNonNull", 0);
        return kIOReturnBadArgument;
    }

    airplayLifeProperty(this, "AIRPLAYPresenceModeDataNonNull", 1);

    this->setProperty(
        "AIRPLAYPresenceModeValue",
        (unsigned long long)data->mode,
        32
    );

    IOLog(
        "AIRPLAY AWDL PRESENCE_MODE: mode=%u\n",
        (unsigned int)data->mode
    );

    airplayLifeProperty(this, "AIRPLAYPresenceModeSuccess", 1);

    return kIOReturnSuccess;
}

IOReturn
AirportItlwmAWDLInterface::setPEER_CACHE_CONTROL(apple80211_peer_cache_control *data)
{
    AirportItlwm *owner = OSDynamicCast(AirportItlwm, getProvider());
    if (owner) owner->peerCacheObserve(true, data);
    /* Trace/probe only: no cache acceptance or completion is fabricated. */
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_OOB_REQUEST(apple80211_awdl_oob_request *data)
{
    /* OOBENTRY: bounded handler-entry diagnostics; no payload reads. */
    static volatile UInt32 oobEntryCount = 0;

    const UInt32 count =
        __sync_add_and_fetch(&oobEntryCount, 1);

    setProperty(
        "AIRPLAYOobHandlerEntryCount",
        (unsigned long long)count,
        32
    );

    setProperty(
        "AIRPLAYOobHandlerDataPresent",
        (unsigned long long)(data != nullptr),
        8
    );
    /* UMI-DIAG-V1: count the actual virtual handler, independent of handleIoctl. */
    const UInt32 umiCalls = __sync_add_and_fetch(&gUmi149Calls, 1);
    setProperty("AIRPLAYUmi149Calls", (unsigned long long)umiCalls, 32);
    if (data != nullptr) {
        const UInt8 *header = reinterpret_cast<const UInt8 *>(data);
        UInt8 record[20] = {}; /* version, call sequence, return, MAC, payload length */
        const UInt32 version = 1, result = (UInt32)kIOReturnUnsupported;
        memcpy(record, &version, 4);
        memcpy(record + 4, &umiCalls, 4);
        memcpy(record + 8, &result, 4);
        memcpy(record + 12, header + 4, 6);
        memcpy(record + 18, header + 40, 2);
        OSData *sample = OSData::withBytes(record, sizeof(record));
        if (sample != nullptr) {
            setProperty("AIRPLAYUmi149Last", sample);
            sample->release();
        }
    }
    airplayDiagOobSample(this, "AIRPLAYDiagOobReqSample", data, &gDiagOobReqSampled);
    setProperty("AIRPLAYUmi149Return", (unsigned long long)(UInt32)kIOReturnUnsupported, 32);
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_SYNC_FRAME_TEMPLATE(
    apple80211_awdl_sync_frame_template *data)
{
    airplayLifeProperty(this, "AIRPLAYSetSyncFrameTemplateEnter", 1);

    if (data == nullptr) {
        airplayLifeProperty(this, "AIRPLAYSetSyncFrameTemplateDataNonNull", 0);
        return kIOReturnBadArgument;
    }

    airplayLifeProperty(this, "AIRPLAYSetSyncFrameTemplateDataNonNull", 1);

    if (data->payload == nullptr || data->payload_len == 0) {
        airplayLifeProperty(this, "AIRPLAYSetSyncFrameTemplatePayloadValid", 0);
        return kIOReturnBadArgument;
    }

    airplayLifeProperty(this, "AIRPLAYSetSyncFrameTemplatePayloadValid", 1);

    AirportItlwm *owner =
        OSDynamicCast(AirportItlwm, getProvider());

    airplayLifeProperty(
        this,
        "AIRPLAYSetSyncFrameTemplateOwnerNonNull",
        owner != nullptr ? 1 : 0
    );

    if (owner == nullptr)
        return kIOReturnError;

    uint8_t *newTemplate =
        (uint8_t *)IOMalloc(data->payload_len);

    if (newTemplate == nullptr)
        return kIOReturnNoMemory;

    memcpy(newTemplate, data->payload, data->payload_len);

    if (owner->syncFrameTemplate != nullptr &&
        owner->syncFrameTemplateLength > 0) {
        IOFree(
            owner->syncFrameTemplate,
            owner->syncFrameTemplateLength
        );
    }

    owner->syncFrameTemplate = newTemplate;
    owner->syncFrameTemplateLength = data->payload_len;

    airplayLifeProperty(this, "AIRPLAYSetSyncFrameTemplateStored", 1);

    IOLog(
        "AIRPLAY AWDL SYNC_FRAME_TEMPLATE: stored payload_len=%u\n",
        data->payload_len
    );

    return kIOReturnSuccess;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_ELECTION_PARAMS(
    apple80211_awdl_election_params *data)
{
    airplayLifeProperty(this, "AIRPLAYElectionEnter", 1);
    airplayLifeProperty(
        this,
        "AIRPLAYElectionDataNonNull",
        data != nullptr ? 1 : 0
    );

    IOLog(
        "AIRPLAY AWDL ELECTION_PARAMS: no-op success data=%s\n",
        data != nullptr ? "non-null" : "null"
    );

    airplayLifeProperty(this, "AIRPLAYElectionSuccess", 1);

    return kIOReturnSuccess;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_PEER_TRAFFIC_REGISTRATION(
    apple80211_awdl_peer_traffic_registration *data)
{
    airplayLifeProperty(this, "AIRPLAYPeerTrafficEnter", 1);

    if (data == nullptr) {
        airplayLifeProperty(this, "AIRPLAYPeerTrafficDataNonNull", 0);
        return kIOReturnBadArgument;
    }

    airplayLifeProperty(this, "AIRPLAYPeerTrafficDataNonNull", 1);

    IOLog(
        "AIRPLAY AWDL PEER_TRAFFIC_REGISTRATION: name_len=%u active=%u\n",
        (unsigned int)data->name_len,
        (unsigned int)data->active
    );

    airplayLifeProperty(this, "AIRPLAYPeerTrafficSuccess", 1);

    return kIOReturnSuccess;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_SECONDARY_MASTER_CHANNEL(
    apple80211_awdl_secondary_master_channel *data)
{
    airplayLifeProperty(this, "AIRPLAYSecondaryMasterEnter", 1);

    if (data == nullptr) {
        airplayLifeProperty(this, "AIRPLAYSecondaryMasterDataNonNull", 0);
        return kIOReturnBadArgument;
    }

    airplayLifeProperty(this, "AIRPLAYSecondaryMasterDataNonNull", 1);

    this->setProperty(
        "AIRPLAYSecondaryMasterChannelValue",
        (unsigned long long)data->secondary_master_channel,
        32
    );

    IOLog(
        "AIRPLAY AWDL SECONDARY_MASTER_CHANNEL: channel=%u\n",
        (unsigned int)data->secondary_master_channel
    );

    airplayLifeProperty(this, "AIRPLAYSecondaryMasterSuccess", 1);

    return kIOReturnSuccess;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_AF_TX_MODE(
    apple80211_awdl_af_tx_mode *data)
{
    airplayLifeProperty(this, "AIRPLAYSetAFTxModeEnter", 1);

    if (data == nullptr) {
        airplayLifeProperty(this, "AIRPLAYSetAFTxModeDataNonNull", 0);
        return kIOReturnBadArgument;
    }

    airplayLifeProperty(this, "AIRPLAYSetAFTxModeDataNonNull", 1);

    IOLog(
        "AIRPLAY AWDL AF_TX_MODE: mode=%llu\n",
        (unsigned long long)data->mode
    );

    return kIOReturnSuccess;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_MIN_RATE(apple80211_awdl_min_rate *data)
{
    airplayLifeProperty(this, "AIRPLAYMinRateEnter", 1);

    if (data == nullptr) {
        airplayLifeProperty(this, "AIRPLAYMinRateDataNonNull", 0);
        return kIOReturnBadArgument;
    }

    airplayLifeProperty(this, "AIRPLAYMinRateDataNonNull", 1);

    IOLog(
        "AIRPLAY AWDL MIN_RATE: min_rate=%u\n",
        (unsigned int)data->min_rate
    );

    airplayLifeProperty(this, "AIRPLAYMinRateSuccess", 1);

    return kIOReturnSuccess;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_ENCRYPTION_KEYS(apple80211_key *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_ENCRYPTION_TYPE(apple80211_encrypt *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_OOB_AUTO_REQUEST(
    apple80211_awdl_oob_request *data)
{
    airplayLifeProperty(this, "AIRPLAYOobAutoEnter", 1);

    if (data == nullptr) {
        airplayLifeProperty(this, "AIRPLAYOobAutoDataNonNull", 0);
        return kIOReturnBadArgument;
    }

    airplayLifeProperty(this, "AIRPLAYOobAutoDataNonNull", 1);

    IOLog(
        "AIRPLAY AWDL OOB_AUTO: data_len=%u unk1=%u unk2=%u unk3=%u "
        "unk4=%u unk5=%u unk6=%u unk7=%u unk9=%u\n",
        (unsigned int)data->data_len,
        (unsigned int)data->unk1,
        (unsigned int)data->unk2,
        (unsigned int)data->unk3,
        (unsigned int)data->unk4,
        (unsigned int)data->unk5,
        (unsigned int)data->unk6,
        (unsigned int)data->unk7,
        (unsigned int)data->unk9
    );

    airplayLifeProperty(this, "AIRPLAYOobAutoSuccess", 1);
    airplayDiagOobSample(this, "AIRPLAYDiagOobAutoSample", data, &gDiagOobAutoSampled); /* DIAGSVC2 */

    return kIOReturnSuccess;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_TXCAL_PERIOD(apple80211_awdl_txcal_period *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_AWDL_ADVERTISERS(awdl_peer_advert_add *data)
{
    /*
     * ADVERTISERS-20261010: IO80211 programs the elected master (44-byte record) here.
     * Broadcom forwards it to firmware ("awdl_advertisers" iovar) and returns success.
     * Intel has no firmware AWDL sync engine: accept + record (no hardware change yet).
     */
    static UInt32 sCalls = 0;
    static UInt32 sNullData = 0;
    sCalls++;
    setProperty("AIRPLAYAdvertisersCalls", (unsigned long long)sCalls, 32);
    if (data == nullptr) {
        sNullData++;
        setProperty("AIRPLAYAdvertisersNullData", (unsigned long long)sNullData, 32);
        return kIOReturnSuccess;
    }

    const uint8_t *b = (const uint8_t *)data;
    uint16_t aw, dc, txDelay, period, extLen;
    uint32_t msBE;
    memcpy(&aw, b + 0x00, 2);
    memcpy(&dc, b + 0x02, 2);
    memcpy(&txDelay, b + 0x04, 2);
    memcpy(&period, b + 0x06, 2);
    memcpy(&extLen, b + 0x0a, 2);
    memcpy(&msBE, b + 0x14, 4);

    OSData *raw = OSData::withBytes(b, 0x2c);
    if (raw != nullptr) {
        setProperty("AIRPLAYAdvertisersLastRecord", raw);
        raw->release();
    }
    OSData *mac = OSData::withBytes(b + 0x26, 6);
    if (mac != nullptr) {
        setProperty("AIRPLAYAdvertisersLastMaster", mac);
        mac->release();
    }
    setProperty("AIRPLAYAdvertisersMasterSet", (unsigned long long)1, 8);
    memcpy(gAirplayPsfMaster, b + 0x26, 6); /* PSFTX-20261015 */
    gAirplayPsfMasterValid = true;
    setProperty("AIRPLAYAdvertisersLastAW", (unsigned long long)aw, 32);
    setProperty("AIRPLAYAdvertisersLastDC", (unsigned long long)dc, 32);
    setProperty("AIRPLAYAdvertisersLastTxDelay", (unsigned long long)txDelay, 32);
    setProperty("AIRPLAYAdvertisersLastPeriod", (unsigned long long)period, 32);
    setProperty("AIRPLAYAdvertisersLastExtLen", (unsigned long long)extLen, 32);
    setProperty("AIRPLAYAdvertisersLastMs", (unsigned long long)OSSwapBigToHostInt32(msBE), 32);

    IOLog("AIRPLAY ADVERTISERS: #%u master %02x:%02x:%02x:%02x:%02x:%02x aw %u dc %u tx_delay %u period %u ms %u\n",
          (unsigned)sCalls, b[0x26], b[0x27], b[0x28], b[0x29], b[0x2a], b[0x2b],
          (unsigned)aw, (unsigned)dc, (unsigned)txDelay, (unsigned)period,
          (unsigned)OSSwapBigToHostInt32(msBE));
    return kIOReturnSuccess;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_DFSP_CONFIG(apple80211_awdl_dfsp_config *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_DFSP_UCSA_CONFIG(apple80211_awdl_dfsp_ucsa_config *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::setCOMPANION_SKYWALK_IF_CREATE(
    apple80211_companion_skywalk_if_create *data)
{
    /* LLWDECLINE: decline the llw0 companion request instead of acking it.
     * Acking success without creating llw0 made wifip2pd wait ~30 s for an
     * interface that never appears, and airportd held WiFi power-on and
     * auto-join behind it. On failure wifip2pd logs "Failed to create the
     * companion low latency interface for AWDL" and continues at once (the
     * same path it took after the timeout). Nothing is created, so the
     * LLW-ID9 / LLW-DEDICATED "no networks" breakage cannot recur. */
    {
        static UInt32 sLLWDeclineCount = 0;
        sLLWDeclineCount++;
        setProperty("AIRPLAYLLWDeclineCount",
            (unsigned long long)sLLWDeclineCount, 32);
    }
    return kIOReturnUnsupported;

    setProperty(
        "AIRPLAYCompanion293Blocked",
        (unsigned long long)1,
        8
    );

    const UInt32 *raw =
        reinterpret_cast<const UInt32 *>(data);

    UInt32 f0 = data ? raw[0] : 0;
    UInt32 f1 = data ? raw[1] : 0;
    UInt32 f2 = data ? raw[2] : 0;
    UInt32 f3 = data ? raw[3] : 0;
    UInt32 f4 = data ? raw[4] : 0;
    UInt32 f5 = data ? raw[5] : 0;

    setProperty("AIRPLAYCompanion293Enter",
        (unsigned long long)1, 8);

    setProperty("AIRPLAYCompanion293Field0",
        (unsigned long long)f0, 32);
    setProperty("AIRPLAYCompanion293Field1",
        (unsigned long long)f1, 32);
    setProperty("AIRPLAYCompanion293Field2",
        (unsigned long long)f2, 32);
    setProperty("AIRPLAYCompanion293Field3",
        (unsigned long long)f3, 32);
    setProperty("AIRPLAYCompanion293Field4",
        (unsigned long long)f4, 32);
    setProperty("AIRPLAYCompanion293Field5",
        (unsigned long long)f5, 32);

    /*
     * Passive companion-request capture only.
     *
     * Do NOT run the old experimental P2P companion creation yet.
     * Preserve current behavior by returning unsupported after
     * recording the request payload.
     */
    setProperty(
        "AIRPLAYCompanion293Captured",
        (unsigned long long)1,
        8
    );

    setProperty(
        "AIRPLAYCompanion293AckSuccess",
        (unsigned long long)1,
        8
    );

    /*
     * ACK-only experiment.
     *
     * Tell IO80211Family the companion request was accepted,
     * but deliberately DO NOT execute the old P2P companion
     * creation code below.
     */
    return kIOReturnSuccess;

    /*
     * Preserve an already-created companion.
     */
    if (gAirplayCompanionP2P != nullptr) {
        setProperty(
            "AIRPLAYCompanionP2PAlreadyExists",
            (unsigned long long)1,
            8
        );

        return kIOReturnSuccess;
    }

    /*
     * Allocate Apple's registered IO80211P2PInterface through
     * the runtime metaclass.  This deliberately avoids:
     *
     *     new IO80211P2PInterface
     *
     * which introduced the unresolved constructor in our
     * previous experiment.
     */
    OSObject *allocated =
        OSMetaClass::allocClassWithName(
            "IO80211P2PInterface"
        );

    setProperty(
        "AIRPLAYCompanionP2PAllocated",
        (unsigned long long)(allocated != nullptr ? 1 : 0),
        8
    );

    if (allocated == nullptr)
        return kIOReturnUnsupported;

    IO80211VirtualInterface *p2p =
        (IO80211VirtualInterface *)allocated;

    IO80211Controller *controller =
        (IO80211Controller *)getProvider();

    setProperty(
        "AIRPLAYCompanionP2PController",
        (unsigned long long)(controller != nullptr ? 1 : 0),
        8
    );

    setProperty(
        "AIRPLAYCompanionP2PMacValid",
        (unsigned long long)(gAirplayAWDLAddressValid ? 1 : 0),
        8
    );

    if (controller == nullptr ||
        !gAirplayAWDLAddressValid) {

        allocated->release();
        return kIOReturnNotReady;
    }

    /*
     * KGP sequence:
     *   init(controller, addr, AWDL role, "awdl")
     *   attach(controller)
     *   registerService()
     */
    bool initialized =
        p2p->init(
            controller,
            &gAirplayAWDLAddress,
            APPLE80211_VIF_AWDL,
            "awdl"
        );

    setProperty(
        "AIRPLAYCompanionP2PInit",
        (unsigned long long)(initialized ? 1 : 0),
        8
    );

    if (!initialized) {
        allocated->release();
        return kIOReturnError;
    }

    bool attached =
        p2p->attach(controller);

    setProperty(
        "AIRPLAYCompanionP2PAttach",
        (unsigned long long)(attached ? 1 : 0),
        8
    );

    if (!attached) {
        p2p->release();
        return kIOReturnError;
    }

    gAirplayCompanionP2P = p2p;

    p2p->registerService();

    setProperty(
        "AIRPLAYCompanionP2PRegistered",
        (unsigned long long)1,
        8
    );

    IOLog(
        "AIRPLAY COMPANION P2P: alloc/init/attach/register success\n"
    );

    return kIOReturnSuccess;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_OOB_SEC_PAYLOAD_REQUEST(apple80211_awdl_af_sec_payload_request *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::setLLW_PARAMS(apple80211_llw_params *data)
{
    airplayLifeProperty(
        this,
        "AIRPLAYSetLLWParamsEnter",
        1
    );

    airplayLifeProperty(
        this,
        "AIRPLAYSetLLWParamsNonNull",
        data != nullptr ? 1 : 0
    );

    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::setTX_RATE(apple80211_tx_rate *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::setP2P_COEX_PROTECTION(
    apple80211_p2p_coex_protection *data)
{
    airplayLifeProperty(this, "AIRPLAYP2PCoexEnter", 1);

    airplayLifeProperty(
        this,
        "AIRPLAYP2PCoexNonNull",
        data != nullptr ? 1 : 0
    );

    IOLog(
        "AIRPLAY AWDL COEX: P2P_COEX_PROTECTION no-op success\n"
    );

    return kIOReturnSuccess;
}

IOReturn
AirportItlwmAWDLInterface::setPSF_DWELL(apple80211_awdl_psf_dwell_params *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_RTG_PEER_STATS_CONFIG(apple80211_rtg_peer_stats_cfg *)
{
    return kIOReturnUnsupported;
}


SInt32
AirportItlwmAWDLInterface::initBSDInterfaceParameters(
    ifnet_init_eparams *params,
    sockaddr_dl **sdl
)
{
    airplayLifeProperty(
        this,
        "AIRPLAYLifeInitBSDEnter",
        1
    );

    SInt32 result =
        IO80211VirtualInterface::initBSDInterfaceParameters(
            params,
            sdl
        );

    UInt8 returnValue = (result == 0) ? 1 : 0;

    airplayLifeProperty(
        this,
        "AIRPLAYLifeInitBSDReturn",
        returnValue
    );

    return result;
}
