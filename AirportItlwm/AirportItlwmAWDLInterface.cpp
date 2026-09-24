#include "AirportItlwmAWDLInterface.hpp"
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
#include <IOKit/skywalk/IOSkywalkTxSubmissionQueue.h>
#include <IOKit/skywalk/IOSkywalkTxCompletionQueue.h>
#include <IOKit/skywalk/IOSkywalkRxSubmissionQueue.h>
#include <IOKit/skywalk/IOSkywalkRxCompletionQueue.h>


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

static UInt32
airplayAWDLTxSubmission(
    OSObject *target,
    IOSkywalkTxSubmissionQueue *,
    IOSkywalkPacket * const *,
    UInt32 count,
    void *)
{
    static AirplayQueueProbe queueProbe = {};
    airplayQueueProbeRecord(target, &queueProbe, count,
        "AIRPLAYQueueTxSubmissionCallsSampled",
        "AIRPLAYQueueTxSubmissionLastCountArg",
        "AIRPLAYQueueTxSubmissionCountArgTotalSampled");
    static UInt32 probeHits = 0;
    if (probeHits < 20) {
        IOLog("AIRPLAY AWDL QUEUE: airplayAWDLTxSubmission hit=%u\n", probeHits + 1);
    }
    probeHits++;
    /*
     * Registration-only experiment.
     *
     * Returning zero deliberately consumes no packets.  The proven
     * Intel mbuf bridge will be reintroduced only after the native
     * AWDL registration/BSD publication path is established.
     */
    return 0;
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


static bool
airplayRegisterNativeAWDL(AirportItlwmAWDLInterface *awdl)
{
    if (awdl == nullptr)
        return false;

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
            0
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

    /*
     * Do NOT write +0x40 yet.  The BCM implementation derives that
     * field conditionally and we have not proved which native branch
     * should apply to Intel.
     */

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
        txSubmission->release();
        txCompletion->release();
        rxSubmission->release();
        rxCompletion->release();
        pool->release();
        return false;
    }

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
    airplayLifeProperty(this, "AIRPLAYLifeStartEnter", 1);
    IOLog(
        "AIRPLAY AWDL LIFE: start ENTER this=%p provider=%p\n",
        this,
        provider
    );

    bool result =
        IO80211VirtualInterface::start(provider);

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
        bool nativeRegistered =
            airplayRegisterNativeAWDL(this);

        airplayLifeProperty(
            this,
            "AIRPLAYNativeRegistrationSuccess",
            nativeRegistered ? 1 : 0
        );

        IOLog(
            "AIRPLAY AWDL LIFE: native registration=%d this=%p\n",
            nativeRegistered ? 1 : 0,
            this
        );

        IOLog(
            "AIRPLAY AWDL LIFE: publishing synchronously "
            "then setRunningState(false) this=%p\n",
            this
        );

        registerService(kIOServiceSynchronous);
        setRunningState(false);
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

SInt32
AirportItlwmAWDLInterface::setInterfaceEnable(bool enabled)
{
    airplayLifeProperty(this, "AIRPLAYLifeSetEnableEnter", 1);

    IOLog(
        "AIRPLAY AWDL LIFE: setInterfaceEnable ENTER this=%p enabled=%d\n",
        this,
        enabled
    );

    SInt32 result =
        IO80211VirtualInterface::setInterfaceEnable(enabled);

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



void
AirportItlwmAWDLInterface::handleIoctl(
    ifnet_t interface,
    unsigned long command,
    void *data
)
{
    if (
        data != nullptr &&
        (
            command == SIOCSA80211 ||
            command == SIOCGA80211
        )
    ) {
        auto *req =
            reinterpret_cast<struct apple80211req *>(data);

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
AirportItlwmAWDLInterface::getPEER_CACHE_MAXIMUM_SIZE(apple80211_peer_cache_maximum_size *)
{
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
AirportItlwmAWDLInterface::getLLW_PARAMS(apple80211_llw_params *)
{
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
AirportItlwmAWDLInterface::setPEER_CACHE_CONTROL(apple80211_peer_cache_control *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_OOB_REQUEST(apple80211_awdl_oob_request *)
{
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

    return kIOReturnSuccess;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_TXCAL_PERIOD(apple80211_awdl_txcal_period *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_AWDL_ADVERTISERS(awdl_peer_advert_add *)
{
    return kIOReturnUnsupported;
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
    const UInt32 *raw = reinterpret_cast<const UInt32 *>(data);

    IOLog(
        "AIRPLAY LLW 293: data=%p field0=%u field1=%u\\n",
        data,
        data != nullptr ? raw[0] : 0,
        data != nullptr ? raw[1] : 0
    );

    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::setAWDL_OOB_SEC_PAYLOAD_REQUEST(apple80211_awdl_af_sec_payload_request *)
{
    return kIOReturnUnsupported;
}

IOReturn
AirportItlwmAWDLInterface::setLLW_PARAMS(apple80211_llw_params *)
{
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
