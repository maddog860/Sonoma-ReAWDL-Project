/* MAC1-PEERCORR-V1 (Debug, observational only).
 * Fixed 16 peer slots keyed by (802.11 peer address, generation, MAC1 epoch,
 * channel). Addresses NEVER leave the private kernel slots. No allocations,
 * blocking, firmware writes or packet changes on RX/TX. Single try-lock writer;
 * missed samples and overflow are counted and NEVER treated as a match.
 * RX provenance = CRC/length accepted MAC1 AWDL BSSID frame; not authenticated.
 * TX provenance = actual AWDL-tagged, encapsulated 802.11 unicast destination.
 * Fresh = independently RX observed no more than 15 s before TX; informational
 * ONLY, not a station admission, peer authentication, or transmit authority.
 */
#ifdef DEBUG
#define MAC1_PEERCORR_V1_OBSERVE_ONLY 1
static_assert(MAC1_PEERCORR_V1_OBSERVE_ONLY == 1,
              "This variant must never arm the peer station experiment");
static const UInt32 kMac1PcSlots=16U;
static const UInt32 kMac1PcFreshSeconds=15U;
static const UInt32 kMac1PcRecycleSeconds=35U;
struct Mac1PcEntry {
    UInt8 peer[6];
    UInt32 generation, epoch, channel;
    UInt32 rxSecond, txSecond, rxCount, txCount, rxMgmt, rxData;
    UInt32 lastMgmtSecond, lastDataSecond;
};
static Mac1PcEntry gMac1PcTable[kMac1PcSlots] = {};
static volatile UInt32 gMac1PcLock=0;
static volatile UInt32 gMac1PcRx=0, gMac1PcTx=0;
static volatile UInt32 gMac1PcRxMgmt=0, gMac1PcRxData=0;
/* Joined to the live Q1 descriptor at submission, then its FW completion. */
static volatile UInt32 gMac1PcJSubmit=0, gMac1PcJCompleted=0;
static volatile UInt32 gMac1PcJ83Data=0, gMac1PcJ83Mgmt=0, gMac1PcJ83Other=0;
static volatile UInt32 gMac1PcJOkData=0, gMac1PcJOkMgmt=0, gMac1PcJOkOther=0;
static volatile UInt32 gMac1PcJOtherOutcome=0, gMac1PcJLastEvidence=0;
static volatile UInt32 gMac1PcFresh=0, gMac1PcTxNoRx=0;
static volatile UInt32 gMac1PcTxOldRx=0, gMac1PcRxAfterTx=0;
static volatile UInt32 gMac1PcChannelMismatch=0, gMac1PcFull=0;
static volatile UInt32 gMac1PcBusy=0, gMac1PcInvalid=0;
static volatile UInt32 gMac1PcEvicted=0, gMac1PcLastVerdict=0;
static volatile UInt32 gMac1PcPublishedSecond=0;
/* Verdict: 1 fresh RX before TX, 2 TX before RX, 3 stale RX,
 * 4 peer seen on another channel, 5 full, 6 busy, 7 invalid.
 */
static void mac1PcObserve(const UInt8 *peer, UInt32 gen, UInt32 channel,
                         bool rx, bool mgmt)
{
    if (!peer || (peer[0] & 1U) || channel==0U || gen==0U) {
        __atomic_fetch_add(&gMac1PcInvalid,1U,__ATOMIC_RELAXED);
        return;
    }
    /* Never wait on a packet path. Writer ownership covers slot selection and
     * updates. Snapshot readers require stable even sequence numbers. */
    UInt32 unlocked=0U;
    if (!__atomic_compare_exchange_n(&gMac1PcLock,&unlocked,1U,false,
                                      __ATOMIC_ACQUIRE,__ATOMIC_RELAXED)) {
        __atomic_fetch_add(&gMac1PcBusy,1U,__ATOMIC_RELAXED);
        if (!rx) __atomic_store_n(&gMac1PcLastVerdict,6U,__ATOMIC_RELAXED);
        return;
    }
    struct timeval now={}; getmicrouptime(&now);
    const UInt32 sec=(UInt32)now.tv_sec;
    const UInt32 epoch=__atomic_load_n(&gMac1LinkV1InvalidateEpoch,__ATOMIC_ACQUIRE);
    int exact=-1, freeSlot=-1, otherChannel=-1;
    for (UInt32 i=0; i<kMac1PcSlots; ++i) {
        Mac1PcEntry &s=gMac1PcTable[i];
        const bool sameEpoch=s.generation==gen && s.epoch==epoch;
        const bool samePeer=sameEpoch && memcmp(s.peer,peer,6)==0;
        if (samePeer && s.channel==channel) { exact=(int)i; break; }
        if (samePeer) otherChannel=(int)i;
        const UInt32 newest=s.rxSecond>s.txSecond?s.rxSecond:s.txSecond;
        if (freeSlot<0 && (s.generation==0U || !sameEpoch ||
              sec<newest || sec-newest>kMac1PcRecycleSeconds)) freeSlot=(int)i;
    }
    int slot=exact>=0?exact:freeSlot;
    if (slot<0) {
        __atomic_fetch_add(&gMac1PcFull,1U,__ATOMIC_RELAXED);
        if (!rx) __atomic_store_n(&gMac1PcLastVerdict,5U,__ATOMIC_RELAXED);
    } else {
        Mac1PcEntry &s=gMac1PcTable[slot];
        if (exact<0) {
            if (s.generation) __atomic_fetch_add(&gMac1PcEvicted,1U,__ATOMIC_RELAXED);
            memset(&s,0,sizeof(s));
            memcpy(s.peer,peer,6);s.generation=gen;s.epoch=epoch;s.channel=channel;
        }
        if (rx) {
            const bool recentTX=s.txSecond!=0U && sec>=s.txSecond &&
                sec-s.txSecond<=kMac1PcFreshSeconds;
            if (recentTX && s.rxSecond==0U)
                __atomic_fetch_add(&gMac1PcRxAfterTx,1U,__ATOMIC_RELAXED);
            s.rxSecond=sec;++s.rxCount;
            if (mgmt) {
                ++s.rxMgmt;s.lastMgmtSecond=sec;
                __atomic_fetch_add(&gMac1PcRxMgmt,1U,__ATOMIC_RELAXED);
            } else {
                ++s.rxData;s.lastDataSecond=sec;
                __atomic_fetch_add(&gMac1PcRxData,1U,__ATOMIC_RELAXED);
            }
            __atomic_fetch_add(&gMac1PcRx,1U,__ATOMIC_RELAXED);
        } else {
            const bool freshRX=s.rxSecond!=0U && sec>=s.rxSecond &&
                sec-s.rxSecond<=kMac1PcFreshSeconds;
            UInt32 verdict=0U;
            if (freshRX) {
                verdict=1U;
                __atomic_fetch_add(&gMac1PcFresh,1U,__ATOMIC_RELAXED);
            } else if (s.rxSecond) {
                verdict=3U;
                __atomic_fetch_add(&gMac1PcTxOldRx,1U,__ATOMIC_RELAXED);
            } else if (otherChannel>=0) {
                verdict=4U;
                __atomic_fetch_add(&gMac1PcChannelMismatch,1U,__ATOMIC_RELAXED);
            } else {
                verdict=2U;
                __atomic_fetch_add(&gMac1PcTxNoRx,1U,__ATOMIC_RELAXED);
            }
            s.txSecond=sec;++s.txCount;
            __atomic_fetch_add(&gMac1PcTx,1U,__ATOMIC_RELAXED);
            __atomic_store_n(&gMac1PcLastVerdict,verdict,__ATOMIC_RELAXED);
        }
    }
    __atomic_store_n(&gMac1PcLock,0U,__ATOMIC_RELEASE);
}
/* Evidence is sampled at the SAME Q1 TX descriptor where TXCTX-V1 records
 * identity and channel. Verdicts: 1=fresh DATA RX, 2=fresh MGMT RX only,
 * 3=stale RX, 4=no RX, 5=peer on a different channel, 6=busy,
 * 7=invalid / unknown channel.  This is matching address observation,
 * NOT authenticated peer identity, delivery, or FW station authority.
 */
static UInt32 mac1PcEvidenceAtDescriptor(const UInt8 *peer, UInt32 gen,
                                        UInt32 channel)
{
    if (!peer || (peer[0]&1U) || !gen || !channel) return 7U;
    UInt32 unlocked=0U;
    if (!__atomic_compare_exchange_n(&gMac1PcLock,&unlocked,1U,false,
                                      __ATOMIC_ACQUIRE,__ATOMIC_RELAXED)) return 6U;
    struct timeval now={};getmicrouptime(&now);
    const UInt32 sec=(UInt32)now.tv_sec;
    const UInt32 epoch=__atomic_load_n(&gMac1LinkV1InvalidateEpoch,__ATOMIC_ACQUIRE);
    UInt32 result=4U;
    bool otherChannel=false, foundExact=false;
    for (UInt32 i=0;i<kMac1PcSlots;++i) {
        const Mac1PcEntry &p=gMac1PcTable[i];
        if (p.generation!=gen || p.epoch!=epoch ||
            memcmp(p.peer,peer,6)!=0) continue;
        if (p.channel!=channel) {otherChannel=true;continue;}
        foundExact=true;
        const bool dataFresh=p.lastDataSecond && sec>=p.lastDataSecond &&
            sec-p.lastDataSecond<=kMac1PcFreshSeconds;
        const bool mgmtFresh=p.lastMgmtSecond && sec>=p.lastMgmtSecond &&
            sec-p.lastMgmtSecond<=kMac1PcFreshSeconds;
        if (dataFresh) result=1U;
        else if (mgmtFresh) result=2U;
        else if (p.rxCount) result=3U;
        else result=4U;
        break;
    }
    if (!foundExact && otherChannel) result=5U;
    __atomic_store_n(&gMac1PcLock,0U,__ATOMIC_RELEASE);
    return result;
}
static void mac1PcJointAtCompletion(UInt32 verdict,UInt32 fwStatus)
{
    __atomic_fetch_add(&gMac1PcJCompleted,1U,__ATOMIC_RELAXED);
    __atomic_store_n(&gMac1PcJLastEvidence,verdict,__ATOMIC_RELAXED);
    if (fwStatus==0x83U) {
        volatile UInt32 *count=verdict==1U?&gMac1PcJ83Data:
            verdict==2U?&gMac1PcJ83Mgmt:&gMac1PcJ83Other;
        __atomic_fetch_add(count,1U,__ATOMIC_RELAXED);
    } else if (fwStatus==IWX_TX_STATUS_SUCCESS) {
        volatile UInt32 *count=verdict==1U?&gMac1PcJOkData:
            verdict==2U?&gMac1PcJOkMgmt:&gMac1PcJOkOther;
        __atomic_fetch_add(count,1U,__ATOMIC_RELAXED);
    } else __atomic_fetch_add(&gMac1PcJOtherOutcome,1U,__ATOMIC_RELAXED);
}
/* Each entry consists of eight 32-bit little-endian (native LE on AX210):
 * index (1..16, zero if empty), generation, channel, RX frames, TX frames,
 * RX age, TX age, flags. No addresses, hashes, unique device identifiers.
 * Flags: bit0 current epoch, bit1 recent RX, bit2 recent TX, bit3 both recent.
 * Slot number is ephemeral; it is not a persistent peer identity.
 */
static void mac1PcPublish(IOEthernetController *ctl, UInt32 generation)
{
    if (!ctl) return;
    /* Registry writes are outside both packet paths and rate-limited to
     * one snapshot per second across the worker and TX post-gate publisher. */
    struct timeval publishNow={};getmicrouptime(&publishNow);
    const UInt32 stamp=(UInt32)publishNow.tv_sec;
    UInt32 last=__atomic_load_n(&gMac1PcPublishedSecond,__ATOMIC_RELAXED);
    if (last==stamp || !__atomic_compare_exchange_n(&gMac1PcPublishedSecond,
             &last,stamp,false,__ATOMIC_ACQ_REL,__ATOMIC_RELAXED)) return;
    ctl->setProperty("AIRPLAYPeerCorrV1Enabled",(unsigned long long)1U,8);
    ctl->setProperty("AIRPLAYPeerCorrV1ObserveOnly",(unsigned long long)1U,8);
    ctl->setProperty("AIRPLAYPeerCorrV2Schema",(unsigned long long)2U,32);
    ctl->setProperty("AIRPLAYPeerCorrV1FreshSeconds",(unsigned long long)kMac1PcFreshSeconds,32);
#define PC_PUBLISH(label,field) ctl->setProperty(label,(unsigned long long)__atomic_load_n(&field,__ATOMIC_RELAXED),32)
    PC_PUBLISH("AIRPLAYPeerCorrV1RxFrames",gMac1PcRx);
    PC_PUBLISH("AIRPLAYPeerCorrV2RxMgmt",gMac1PcRxMgmt);
    PC_PUBLISH("AIRPLAYPeerCorrV2RxData",gMac1PcRxData);
    PC_PUBLISH("AIRPLAYPeerCorrV2JSubmit",gMac1PcJSubmit);
    PC_PUBLISH("AIRPLAYPeerCorrV2JCompleted",gMac1PcJCompleted);
    PC_PUBLISH("AIRPLAYPeerCorrV2J83Data",gMac1PcJ83Data);
    PC_PUBLISH("AIRPLAYPeerCorrV2J83Mgmt",gMac1PcJ83Mgmt);
    PC_PUBLISH("AIRPLAYPeerCorrV2J83OtherEvidence",gMac1PcJ83Other);
    PC_PUBLISH("AIRPLAYPeerCorrV2JOkData",gMac1PcJOkData);
    PC_PUBLISH("AIRPLAYPeerCorrV2JOkMgmt",gMac1PcJOkMgmt);
    PC_PUBLISH("AIRPLAYPeerCorrV2JOkOtherEvidence",gMac1PcJOkOther);
    PC_PUBLISH("AIRPLAYPeerCorrV2JOtherFwStatus",gMac1PcJOtherOutcome);
    PC_PUBLISH("AIRPLAYPeerCorrV2JLastEvidence",gMac1PcJLastEvidence);
    PC_PUBLISH("AIRPLAYPeerCorrV1TxFrames",gMac1PcTx);
    PC_PUBLISH("AIRPLAYPeerCorrV1TxFreshRx",gMac1PcFresh);
    PC_PUBLISH("AIRPLAYPeerCorrV1TxNoRx",gMac1PcTxNoRx);
    PC_PUBLISH("AIRPLAYPeerCorrV1TxStaleRx",gMac1PcTxOldRx);
    PC_PUBLISH("AIRPLAYPeerCorrV1RxAfterTx",gMac1PcRxAfterTx);
    PC_PUBLISH("AIRPLAYPeerCorrV1TxOtherChannel",gMac1PcChannelMismatch);
    PC_PUBLISH("AIRPLAYPeerCorrV1TableFull",gMac1PcFull);
    PC_PUBLISH("AIRPLAYPeerCorrV1Busy",gMac1PcBusy);
    PC_PUBLISH("AIRPLAYPeerCorrV1Invalid",gMac1PcInvalid);
    PC_PUBLISH("AIRPLAYPeerCorrV1Recycled",gMac1PcEvicted);
    PC_PUBLISH("AIRPLAYPeerCorrV1LastVerdict",gMac1PcLastVerdict);
#undef PC_PUBLISH
    UInt32 snapshot[kMac1PcSlots*8U]={};
    bool stable=false;
    const UInt32 epoch=__atomic_load_n(&gMac1LinkV1InvalidateEpoch,__ATOMIC_ACQUIRE);
    struct timeval now={};getmicrouptime(&now);
    const UInt32 sec=(UInt32)now.tv_sec;
    /* A nonblocking table lock gives an internally consistent snapshot and
     * ensures no nonatomic slot read races with an RX/TX writer. Never hold
     * the lock while publishing/allocating an OSData object. */
    UInt32 unlocked=0U;
    stable=__atomic_compare_exchange_n(&gMac1PcLock,&unlocked,1U,false,
                                       __ATOMIC_ACQUIRE,__ATOMIC_RELAXED);
    if (stable) {
        for (UInt32 i=0; i<kMac1PcSlots; ++i) {
            const Mac1PcEntry &s=gMac1PcTable[i];
            UInt32 *v=&snapshot[i*8U];
            const bool recentRx=s.rxSecond && sec>=s.rxSecond &&
                sec-s.rxSecond<=kMac1PcFreshSeconds;
            const bool recentTx=s.txSecond && sec>=s.txSecond &&
                sec-s.txSecond<=kMac1PcFreshSeconds;
            v[0]=s.generation?i+1U:0U;v[1]=s.generation;v[2]=s.channel;
            v[3]=s.rxCount;v[4]=s.txCount;
            v[5]=s.rxSecond && sec>=s.rxSecond ? sec-s.rxSecond : 0xffffffffU;
            v[6]=s.txSecond && sec>=s.txSecond ? sec-s.txSecond : 0xffffffffU;
            v[7]=((s.generation==generation && s.epoch==epoch)?1U:0U) |
                 (recentRx?2U:0U) | (recentTx?4U:0U) |
                 ((recentRx && recentTx)?8U:0U);
        }
        __atomic_store_n(&gMac1PcLock,0U,__ATOMIC_RELEASE);
    }
    ctl->setProperty("AIRPLAYPeerCorrV1SnapshotStable",(unsigned long long)stable,8);
    if (stable) {
        OSData *data=OSData::withBytes(snapshot,sizeof(snapshot));
        if (data) {ctl->setProperty("AIRPLAYPeerCorrV1Slots",data);data->release();}
    }
}
#endif /* DEBUG */
