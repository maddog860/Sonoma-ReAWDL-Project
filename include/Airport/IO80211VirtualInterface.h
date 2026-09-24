#ifndef IO80211VirtualInterface_h
#define IO80211VirtualInterface_h

#if !defined(IO80211FAMILY_V2)

#include "IO80211VirtualInterfaceLegacy.h"

#else

#include "IO80211SkywalkInterface.h"
#include "apple_private_spi.h"

class IO80211Controller;
struct packet_info_tx;

class IO80211VirtualInterface : public IO80211SkywalkInterface {
    OSDeclareDefaultStructors(IO80211VirtualInterface)

public:

    /*
     * Sonoma V2 overrides of IO80211SkywalkInterface /
     * IOSkywalk* / IOService.
     *
     * Apple vtable comparison proves these occupy existing
     * inherited slots and DO NOT append new slots.
     */

    virtual void free(void) APPLE_KEXT_OVERRIDE;

    virtual IOReturn configureReport(
        IOReportChannelList *,
        UInt,
        void *,
        void *
    ) APPLE_KEXT_OVERRIDE;

    virtual IOReturn updateReport(
        IOReportChannelList *,
        UInt,
        void *,
        void *
    ) APPLE_KEXT_OVERRIDE;

    virtual bool start(IOService *) APPLE_KEXT_OVERRIDE;
    virtual void stop(IOService *) APPLE_KEXT_OVERRIDE;

    virtual bool terminate(
        IOOptionBits options = 0
    ) APPLE_KEXT_OVERRIDE;

    virtual bool attach(
        IOService *
    ) APPLE_KEXT_OVERRIDE;

    virtual void detach(
        IOService *
    ) APPLE_KEXT_OVERRIDE;

    virtual IOReturn newUserClient(
        task_t,
        void *,
        UInt,
        OSDictionary *,
        IOUserClient **
    ) APPLE_KEXT_OVERRIDE;

    virtual const char *stringFromReturn(
        int
    ) APPLE_KEXT_OVERRIDE;

    virtual IOReturn enable(
        UInt
    ) APPLE_KEXT_OVERRIDE;

    virtual bool prepareBSDInterface(
        ifnet_t,
        UInt
    ) APPLE_KEXT_OVERRIDE;

    virtual IOReturn processBSDCommand(
        ifnet_t,
        UInt,
        void *
    ) APPLE_KEXT_OVERRIDE;

    virtual SInt32 setInterfaceEnable(
        bool
    ) APPLE_KEXT_OVERRIDE;

    virtual UInt32 getFeatureFlags(
        void
    ) APPLE_KEXT_OVERRIDE;

    virtual bool bpfTap(
        UInt,
        UInt
    ) APPLE_KEXT_OVERRIDE;

    virtual void setHardwareAddress(
        ether_addr *
    ) APPLE_KEXT_OVERRIDE;

    virtual bool setMulticastAddresses(
        ether_addr const *,
        UInt
    ) APPLE_KEXT_OVERRIDE;

    virtual void *createPeerManager(
        void
    ) APPLE_KEXT_OVERRIDE;

    virtual void postMessage(
        UInt,
        void *,
        unsigned long,
        bool
    ) APPLE_KEXT_OVERRIDE;

    virtual void logTxPacket(
        IO80211NetworkPacket *,
        PacketSkywalkScratch *,
        apple80211_wme_ac,
        bool
    ) APPLE_KEXT_OVERRIDE;

    virtual void logTxCompletionPacket(
        IO80211NetworkPacket *,
        PacketSkywalkScratch *,
        unsigned char *,
        apple80211_wme_ac,
        int,
        UInt,
        bool
    ) APPLE_KEXT_OVERRIDE;

    virtual IOReturn inputPacket(
        IO80211NetworkPacket *,
        packet_info_tag *,
        ether_header *,
        bool *
    ) APPLE_KEXT_OVERRIDE;

    virtual void logSkywalkTxReqPacket(
        IO80211NetworkPacket *,
        PacketSkywalkScratch *,
        unsigned char *,
        apple80211_wme_ac,
        bool
    ) APPLE_KEXT_OVERRIDE;

    virtual SInt64 pendingPackets(
        unsigned char
    ) APPLE_KEXT_OVERRIDE;

    virtual SInt64 packetSpace(
        unsigned char
    ) APPLE_KEXT_OVERRIDE;

    virtual IO80211LinkState linkState(
        void
    ) APPLE_KEXT_OVERRIDE;

    virtual void setScanningState(
        UInt,
        bool,
        apple80211_scan_data *,
        int
    ) APPLE_KEXT_OVERRIDE;

    virtual void updateLinkParameters(
        apple80211_interface_availability *
    ) APPLE_KEXT_OVERRIDE;

    virtual void updateInterfaceCoexRiskPct(
        unsigned long long
    ) APPLE_KEXT_OVERRIDE;

    virtual void setInterfaceNF(
        apple80211_channel,
        long long
    ) APPLE_KEXT_OVERRIDE;

    virtual void setDebugFlags(
        unsigned long long,
        UInt
    ) APPLE_KEXT_OVERRIDE;

    virtual SInt64 debugFlags(
        void
    ) APPLE_KEXT_OVERRIDE;

    virtual void setInterfaceChipCounters(
        apple80211_stat_report *,
        apple80211_chip_counters_tx *,
        apple80211_chip_error_counters_tx *,
        apple80211_chip_counters_rx *
    ) APPLE_KEXT_OVERRIDE;

    virtual void setInterfaceMIBdot11(
        apple80211_stat_report *,
        apple80211_ManagementInformationBasedot11_counters *
    ) APPLE_KEXT_OVERRIDE;

    virtual void setFrameStats(
        apple80211_stat_report *,
        apple80211_frame_counters *
    ) APPLE_KEXT_OVERRIDE;

#if __IO80211_TARGET >= __MAC_14_4
    virtual void setInfraSpecificFrameStats(
        apple80211_stat_report *,
        apple80211_infra_specific_stats *
    ) APPLE_KEXT_OVERRIDE;
#endif

    virtual SInt64 getWmeTxCounters(
        unsigned long long *
    ) APPLE_KEXT_OVERRIDE;

    virtual void setEnabledBySystem(
        bool
    ) APPLE_KEXT_OVERRIDE;

    virtual bool enabledBySystem(
        void
    ) APPLE_KEXT_OVERRIDE;

    virtual void setWoWEnabled(
        bool
    ) APPLE_KEXT_OVERRIDE;

    virtual bool wowEnabled(
        void
    ) APPLE_KEXT_OVERRIDE;

    virtual void printDataPath(
        userPrintCtx *
    ) APPLE_KEXT_OVERRIDE;

    virtual bool findOrCreateFlowQueue(
        IO80211FlowQueueHash
    ) APPLE_KEXT_OVERRIDE;

    virtual UInt64 findOrCreateFlowQueueWithCache(
        IO80211FlowQueueHash,
        bool *
    ) APPLE_KEXT_OVERRIDE;

    virtual UInt64 findExistingFlowQueue(
        IO80211FlowQueueHash
    ) APPLE_KEXT_OVERRIDE;

    virtual void removePacketQueue(
        IO80211FlowQueueHash const *
    ) APPLE_KEXT_OVERRIDE;

    virtual void flushPacketQueues(
        void
    ) APPLE_KEXT_OVERRIDE;

    virtual void cachePeer(
        ether_addr *,
        UInt *
    ) APPLE_KEXT_OVERRIDE;

    virtual bool shouldLog(
        unsigned long long
    ) APPLE_KEXT_OVERRIDE;

    virtual void vlogDebug(
        unsigned long long,
        char const *,
        va_list
    ) APPLE_KEXT_OVERRIDE;

    virtual void vlogDebugBPF(
        unsigned long long,
        char const *,
        va_list
    ) APPLE_KEXT_OVERRIDE;

    virtual void *getP2PSkywalkPeerMgr(
        void
    ) APPLE_KEXT_OVERRIDE;

    virtual int getEventPipeSize(
        void
    ) APPLE_KEXT_OVERRIDE;

    virtual UInt64 createEventPipe(
        IO80211APIUserClient *
    ) APPLE_KEXT_OVERRIDE;


    /*
     * Apple Sonoma IO80211VirtualInterface appended vtable:
     *
     * 448-470 = 23 real methods.
     *
     * Declaration ORDER BELOW MATTERS.
     */

    // 448
    virtual bool init(
        IO80211Controller *,
        ether_addr *,
        UInt,
        char const *
    );

    // 449
    virtual void setLinkState(
        IO80211LinkState,
        UInt
    );

    // 450
    // Return type not encoded in the Apple symbol.
    // Placeholder is sufficient for vtable reconstruction.
    virtual void forwardPacket(
        IO80211NetworkPacket *
    );

    // 451
    virtual void handleIoctl(
        ifnet_t,
        unsigned long,
        void *
    );

    // 452
    virtual void addPeerToCache(
        unsigned char *
    );

    // 453
    virtual void deletePeerFromCache(
        unsigned char *
    );

    // 454
    virtual bool handleDebugCmd(
        apple80211_debug_command *
    );

    // 455
    virtual bool isOutputFlowControlled(
        void
    );

    // 456
    virtual void setOutputFlowControlled(
        void
    );

    // 457
    virtual void clearOutputFlowControlled(
        void
    );

    // 458
    virtual UInt32 configureAQMOutput(
        void
    );

    // 459
    virtual bool attachToBpf(
        void
    );

    // 460
    virtual bool configureIfnet(
        void
    );

    // 461
    virtual void reset(
        void
    );

    // 462
    virtual void dupAndTransmitMcastPacket(
        IO80211NetworkPacket *,
        unsigned char *,
        unsigned char *
    );

    // 463
    virtual void freeMulticastPacket(
        IO80211NetworkPacket *
    );

    // 464
    virtual void triggerAWDLMulticastTx(
        UInt,
        unsigned char
    );

    // 465
    virtual void p2pMulticastTx(
        IO80211NetworkPacket **,
        UInt
    );

    // 466
    virtual void sendPendingPacketsToStack(
        IO80211NetworkPacket **,
        UInt
    );

    // 467
    virtual void freePendingPackets(
        IO80211NetworkPacket **,
        UInt
    );

    // 468
    virtual UInt32 outputPacket(
        mbuf_t,
        void *
    );

    // 469
    virtual UInt32 inputPacket(
        mbuf_t,
        packet_info_tag *
    );

    // 470
    virtual void reportTransmitStatus(
        mbuf_t,
        int,
        packet_info_tx *
    );


    /*
     * 471-486: exact Apple reserved tail.
     */

    OSMetaClassDeclareReservedUnused(IO80211VirtualInterface,  0);
    OSMetaClassDeclareReservedUnused(IO80211VirtualInterface,  1);
    OSMetaClassDeclareReservedUnused(IO80211VirtualInterface,  2);
    OSMetaClassDeclareReservedUnused(IO80211VirtualInterface,  3);
    OSMetaClassDeclareReservedUnused(IO80211VirtualInterface,  4);
    OSMetaClassDeclareReservedUnused(IO80211VirtualInterface,  5);
    OSMetaClassDeclareReservedUnused(IO80211VirtualInterface,  6);
    OSMetaClassDeclareReservedUnused(IO80211VirtualInterface,  7);
    OSMetaClassDeclareReservedUnused(IO80211VirtualInterface,  8);
    OSMetaClassDeclareReservedUnused(IO80211VirtualInterface,  9);
    OSMetaClassDeclareReservedUnused(IO80211VirtualInterface, 10);
    OSMetaClassDeclareReservedUnused(IO80211VirtualInterface, 11);
    OSMetaClassDeclareReservedUnused(IO80211VirtualInterface, 12);
    OSMetaClassDeclareReservedUnused(IO80211VirtualInterface, 13);
    OSMetaClassDeclareReservedUnused(IO80211VirtualInterface, 14);
    OSMetaClassDeclareReservedUnused(IO80211VirtualInterface, 15);

public:

    /*
     * Apple physical ABI:
     *
     * IO80211SkywalkInterface = 0x118
     * IO80211VirtualInterface = 0x120
     */
    char buf[0x08];
};

static_assert(
    sizeof(IO80211VirtualInterface) == 0x120,
    "Sonoma IO80211VirtualInterface ABI size mismatch"
);

#endif /* IO80211FAMILY_V2 */

#endif /* IO80211VirtualInterface_h */
