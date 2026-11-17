/* Exact nonvirtual exported getter ABI, receiver in RDI; no class-layout edits. */
extern "C" void *pcpGetDataPathManager(void *)
    __asm__("__ZN18IO80211PeerManager21getP2PDataPathManagerEv");
extern "C" UInt32 pcpGetCurrentCount(void *)
    __asm__("__ZN25IO80211P2PDataPathManager23getCurrentPeerCacheSizeEv");
extern "C" UInt32 pcpGetMaximumCount(void *)
    __asm__("__ZN25IO80211P2PDataPathManager19getMaxPeerCacheSizeEv");
struct PeerCacheNativeCall { void *manager; const AirplayUmiSnapshotV1 *umi; };
static void peerCacheObserveNative(AirportItlwm *airport, void *manager,
    const AirplayUmiSnapshotV1 *umi)
{
    if(airport) airport->peerCacheNativeSample(manager,umi);
}
void AirportItlwm::peerCacheNativeSample(void *manager,const void *sample)
{
    if(!manager || !sample || !getCommandGate() ||
        __atomic_load_n(&fAddrSyncStopping,__ATOMIC_ACQUIRE)) return;
    PeerCacheNativeCall call{manager,static_cast<const AirplayUmiSnapshotV1 *>(sample)};
    // Never block the RX worker on controller teardown or another native call.
    getCommandGate()->attemptAction(peerCacheNativeAction,&call);
}
IOReturn AirportItlwm::peerCacheNativeAction(OSObject *target,void *arg,void *,void *,void *)
{
    AirportItlwm *airport=OSDynamicCast(AirportItlwm,target);
    if(!airport || !arg || __atomic_load_n(&airport->fAddrSyncStopping,__ATOMIC_ACQUIRE) ||
        !airport->fSonomaAWDLInterface) return kIOReturnNotReady;
    PeerCacheNativeCall &call=*static_cast<PeerCacheNativeCall *>(arg);
    uint8_t *iv=airplayRxFeedIvars(airport->fSonomaAWDLInterface);
    void *manager=iv?*reinterpret_cast<void **>(iv+0x30):nullptr;
    if(!manager || manager!=call.manager) return kIOReturnNotReady;
    const AirplayUmiSnapshotV1 *umi=call.umi;
    static volatile UInt32 sequence=0;
    static_assert(sizeof(AirplayUmiSnapshotV1)==64,"UMI schema");

    PeerCacheNativeV1 r={};r.w[0]=0x31534e50;r.w[1]=1;r.w[2]=sizeof(r);
    r.w[3]=__atomic_add_fetch(&sequence,1U,__ATOMIC_RELAXED);
    void *dpm=pcpGetDataPathManager(manager);r.w[4]=dpm!=nullptr;
    r.w[5]=r.w[6]=r.w[7]=r.w[12]=0xffffffffU;
    if (dpm) {
        r.w[6]=pcpGetMaximumCount(dpm);r.w[5]=pcpGetCurrentCount(dpm);r.w[7]=pcpGetMaximumCount(dpm);
        r.w[8]=r.w[6]==r.w[7];
    } else r.w[11]=ENXIO;
    ItlIwx *iwx=OSDynamicCast(ItlIwx,airport->fHalService);
    r.w[9]=iwx?UInt32(iwx->com.sc_generation):0xffffffffU;r.w[10]=umi->sequence;
    if (umi->fw240 || umi->fw241) r.w[12]=1;
    else if (dpm && r.w[8]) r.w[12]=r.w[5]<r.w[6];
    r.w[13]=umi->localSupport && umi->peerSupport && !umi->localDisabled;
    r.w[14]=umi->options || umi->options2 || umi->reliable;
    r.w[15]=umi->waitingOnChain;
    memcpy(r.umi,umi,sizeof(*umi));
    OSData *data=OSData::withBytes(&r,sizeof(r));
    if (data) {airport->setProperty("AIRPLAYPeerCacheNativeV1",data);data->release();}
    return kIOReturnSuccess;
}
