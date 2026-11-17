/* PEER-CACHE-PROBE-V1: a new, separately armed station-only experiment.
 * No queue allocation, DMA allocation, packet submission, or native completion.
 * All mutable probe state is owned by this ItlIwx and its existing ns task.
 */
#if defined(AIRPORT) && defined(__IO80211_TARGET) && __IO80211_TARGET >= __MAC_14_4
extern "C" bool AirportItlwmPeerCacheCopyCandidate(void *,PeerCacheCandidateV1 *);
/* V30B peer-cache isolation: firmware actions permanently OFF.
 * Keep the S6/S7 opt-in experiment separately active.
 * The original peer-cache source is preserved in the V30 parent tree. */
#define MAC1S3_V30B_PEER_PROBE_DISABLED 1
static_assert(MAC1S3_V30B_PEER_PROBE_DISABLED == 1 &&
              MAC1TX_S6_STATION_WRITES_APPROVED == 1 &&
              MAC1TX_S7_FW_QUEUE_WRITES_APPROVED == 1 &&
              MAC1TX_S6_QUEUE_WRITES_APPROVED == 0 &&
              MAC1TX_S6_DMA_EXERCISE_APPROVED == 0 &&
              MAC1TX_S6_TX_REROUTE_APPROVED == 0 &&
              MAC1TX_S7_TX_REROUTE_APPROVED == 0 &&
              MAC1TX_S1_FIRMWARE_WRITE_REVIEWED == 0,
              "V30B peer-cache isolated; only S6/S7 one-shot FW opt-in allowed");
static_assert(sizeof(struct iwx_add_sta_cmd)==48,"firmware ADD_STA shape");
static_assert(sizeof(struct iwx_rm_sta_cmd)==4,"firmware REMOVE_STA shape");
static_assert(offsetof(struct iwx_add_sta_cmd,sta_id)==16 &&
    offsetof(struct iwx_add_sta_cmd,station_type)==35,"station command offsets");
/* LINK station testing is a separate Debug-only opt-in. The original
 * -awdlpeerprobe must ALSO be set. No queue/DMA/TX changes in this mode.
 * The existing GENERAL_PURPOSE probe is unchanged without this flag.
 */
static bool peerCacheLinkProbeRequested()
{
#ifdef DEBUG
    static int cached = -1;
    if (cached < 0) {int n=0;cached=PE_parse_boot_argn("-awdlpeerlink",&n,sizeof(n))?1:0;}
    return cached == 1;
#else
    return false;
#endif
}
static bool peerCacheStationProbeRequested()
{
    /* V30B: permanently suppress peer-cache ADD/REMOVE requests. */
    return false;
}
/* MAC1-LINK-HOLD-V2: the only active experiment is a single already-validated
 * LINK station. The default one-shot registration is unchanged without this
 * third Debug-only opt-in. Never enable S6/S7 queue/DMA features here.
 */
static bool peerCacheLinkHoldRequested()
{
#ifdef DEBUG
    static int cached=-1;
    if (cached<0) {int n=0;cached=PE_parse_boot_argn("-awdlpeerhold",&n,sizeof(n))?1:0;}
    return cached==1 && peerCacheLinkProbeRequested() && peerCacheStationProbeRequested();
#else
    return false;
#endif
}
static const UInt32 kPeerLinkHoldSeconds = 20U;
/* These functions use a separate one-shot timer, defined in ItlIwx.cpp after
 * this include. Firmware commands remain exclusively on the NS task queue.
 */
static void mac1LinkHoldArmTimer(void);
static volatile UInt32 gMac1LinkHoldExitReason=0U;
static volatile UInt32 gMac1LinkHoldPending=0U; /* atomic timer-to-NS-task signal */
void ItlIwx::iwx_peer_cache_probe_publish(struct iwx_softc *sc,bool force)
{
    IOEthernetController *ctl=getController();if(!ctl)return;
    struct timeval now;getmicrouptime(&now);
    if (!force && fPeerProbeLastPublishSecond==uint64_t(now.tv_sec)) return;
    fPeerProbeLastPublishSecond=uint64_t(now.tv_sec);
    ++fPeerProbe.w[3];fPeerProbe.w[7]=UInt32(sc->sc_generation);
    fPeerProbe.w[27]=sc->sc_uc.uc_ok!=0;
    fPeerProbe.w[36]=__atomic_load_n(&fCmd2KFrozen,__ATOMIC_SEQ_CST);
    fPeerProbe.w[37]=sc->sc_flags;
    OSData *data=OSData::withBytes(&fPeerProbe,sizeof(fPeerProbe));
    if(data){ctl->setProperty("AIRPLAYPeerStationProbeV1",data);data->release();}
    ctl->setProperty("AIRPLAYPeerStationProbeRequested",peerCacheStationProbeRequested());
    ctl->setProperty("AIRPLAYPeerStationProbeAttempts",(unsigned long long)fPeerProbe.w[6],32);
    ctl->setProperty("AIRPLAYPeerStationProbePhase",(unsigned long long)fPeerProbe.w[4],32);
    ctl->setProperty("AIRPLAYPeerLinkV1Requested", (unsigned long long)peerCacheLinkProbeRequested(), 8);
    ctl->setProperty("AIRPLAYPeerLinkV1StationType", (unsigned long long)fPeerProbe.w[31], 8);
    ctl->setProperty("AIRPLAYPeerLinkV1TXDestMatch", (unsigned long long)fPeerProbe.w[32], 8);
    ctl->setProperty("AIRPLAYPeerLinkV1GuardMask", (unsigned long long)fPeerProbe.w[9], 32);
    ctl->setProperty("AIRPLAYPeerHoldV2Requested", (unsigned long long)peerCacheLinkHoldRequested(), 8);
    ctl->setProperty("AIRPLAYPeerHoldV2ElapsedSeconds", (unsigned long long)fPeerProbe.w[33], 32);
    ctl->setProperty("AIRPLAYPeerHoldV2PeriodSeconds", (unsigned long long)kPeerLinkHoldSeconds, 32);
    ctl->setProperty("AIRPLAYPeerHoldV2ExitReason", (unsigned long long)__atomic_load_n(
        &gMac1LinkHoldExitReason, __ATOMIC_RELAXED), 8);
    ctl->setProperty("AIRPLAYPeerHoldV2NoQueueOrReroute", (unsigned long long)1, 8);
#ifdef DEBUG
    ctl->setProperty("AIRPLAYPeerLinkV1TXDestCaptured", (unsigned long long)
        __atomic_load_n(&gMac1LinkTxDestCaptured, __ATOMIC_RELAXED), 32);
#endif
}
void ItlIwx::iwx_peer_cache_probe(struct iwx_softc *sc)
{
    /* V30B: old firmware probe deliberately inert; not a runtime switch. */
    (void)sc;
    return;
}
#endif
