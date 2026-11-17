/* PEER-CACHE-PROBE-V1: serialize capture/selection, never accept a cache op. */
struct PeerCacheObserveCall { bool setter; const void *data; };
extern "C" bool AirportItlwmPeerCacheCopyCandidate(void *owner, PeerCacheCandidateV1 *out)
{
    AirportItlwm *self = OSDynamicCast(AirportItlwm, static_cast<IOEthernetController *>(owner));
    return self && self->peerCacheCopyCandidate(out);
}
IOReturn AirportItlwm::peerCacheObserve(bool setter, const void *data)
{
    ItlIwx *iwx = OSDynamicCast(ItlIwx, fHalService);
    if (!iwx || iwx->com.sc_device_family != IWX_DEVICE_FAMILY_AX210 || !getCommandGate() ||
        __atomic_load_n(&fAddrSyncStopping,__ATOMIC_ACQUIRE)) return kIOReturnNotReady;
    PeerCacheObserveCall call{setter,data};
    return getCommandGate()->runAction(peerCacheObserveAction,&call);
}
IOReturn AirportItlwm::peerCacheObserveAction(OSObject *target, void *arg,
    void *, void *, void *)
{
    AirportItlwm *self = OSDynamicCast(AirportItlwm,target);
    if (!self || __atomic_load_n(&self->fAddrSyncStopping,__ATOMIC_ACQUIRE)) return kIOReturnNotReady;
    ItlIwx *iwx = OSDynamicCast(ItlIwx,self->fHalService);
    if (!iwx) return kIOReturnNotReady;
    PeerCacheObserveCall &call=*static_cast<PeerCacheObserveCall *>(arg);
    PeerCacheRequestV1 &r=self->fPeerCacheRequest;
    r.w[0]=0x31524350; r.w[1]=1; r.w[2]=sizeof(r); ++r.w[3];
    r.w[4]=call.setter?143U:130U; r.w[5]=0xffffffffU; r.w[6]=0xffffffffU;
    r.w[7]=0; r.w[8]=UInt32(iwx->com.sc_generation); r.w[9]=UInt32(kIOReturnUnsupported);
    struct timeval now; getmicrouptime(&now);
    r.w[10]=UInt32(now.tv_sec); r.w[11]=UInt32(uint64_t(now.tv_sec)>>32); r.w[12]=UInt32(now.tv_usec);
    if (call.setter) ++r.w[13]; else ++r.w[14];
    if (!call.data) ++r.w[15];
    memset(r.local,0,sizeof(r.local));memset(r.peer,0,sizeof(r.peer));memset(r.prefix,0,sizeof(r.prefix));
    const bool localValid=AirportItlwmAWDLCurrentAddr(r.local) && awdlAddressValid(r.local);
    r.w[23]=0;
    if (call.setter) {
        if (call.data) {
            memcpy(r.prefix,call.data,4); r.w[23]=4; r.w[5]=pcLE32(r.prefix);
            /* The verified private callback ABI supplies a full request.
             * Read only its fixed 64-byte prefix, and only for version 1. */
            if (r.w[5]==1) {memcpy(r.prefix,call.data,64);r.w[23]=64;r.w[6]=pcLE32(r.prefix+4);memcpy(r.peer,r.prefix+8,6);}
        }
        r.w[7]=call.data?pcParsePrefix(r.prefix,r.w[23]):PC_NULL;
        if (localValid && awdlAddressEqual(r.peer,r.local)) r.w[7]|=PC_SELF;

        /* V2: one-shot, read-only capture of Sonoma's 464-byte ADD.
         * No firmware writes, station allocation, or completion change. */
        if (call.data && r.w[23] == 64 && r.w[5] == 1 &&
            r.w[6] == 0 && r.w[7] == 0 &&
            !self->getProperty("AIRPLAYPeerCacheFullAddV2")) {

            OSData *full = OSData::withBytes(call.data, 464);
            if (full) {
                if (self->setProperty("AIRPLAYPeerCacheFullAddV2", full)) {
                    self->setProperty("AIRPLAYPeerCacheFullAddV2Bytes",
                        464ULL, 32);
                    self->setProperty("AIRPLAYPeerCacheFullAddV2Seq",
                        (unsigned long long)r.w[3], 32);
                    self->setProperty("AIRPLAYPeerCacheFullAddV2Generation",
                        (unsigned long long)r.w[8], 32);
                }
                full->release();
            }
        }
        if (r.w[7]) ++r.w[16];
        if (r.w[6]==0) ++r.w[17];
        if (r.w[6]==6) ++r.w[18];
        if (r.w[6]==2) ++r.w[19];
        if (!r.w[7] && r.w[6]==2 &&
            self->fPeerCacheCandidate.generation==r.w[8] &&
            awdlAddressEqual(self->fPeerCacheCandidate.peer,r.peer)) {
            self->fPeerCacheCandidate={};++r.w[21];
        }
        if (!r.w[7] && localValid && (r.w[6]==0 || r.w[6]==6)) {
            PeerCacheCandidateV1 next={};next.sequence=r.w[3];next.generation=r.w[8];next.seconds=UInt32(now.tv_sec);
            memcpy(next.peer,r.peer,6);memcpy(next.local,r.local,6);
            self->fPeerCacheCandidate=next;++r.w[20];
        }
    }
    r.w[22]=__atomic_load_n(&self->fPeerCacheGateMisses,__ATOMIC_RELAXED);
    OSData *data=OSData::withBytes(&r,sizeof(r));
    if (data) {self->setProperty("AIRPLAYPeerCacheRequestV1",data);data->release();}
    if (call.setter) {
        OSData *sample=OSData::withBytes(&r,sizeof(r));
        if (sample) {self->setProperty("AIRPLAYPeerCacheLastSetterV1",sample);sample->release();}
    }
    self->setProperty("AIRPLAYPeerCacheSetterCalls",(unsigned long long)r.w[13],32);
    self->setProperty("AIRPLAYPeerCacheGetterCalls",(unsigned long long)r.w[14],32);
    self->setProperty("AIRPLAYPeerCacheInvalidCalls",(unsigned long long)r.w[16],32);
    if (call.setter) IOLog("AIRPLAY PEER-CACHE-PROBE-V1: request=%u op=%u validation=0x%x gen=%u; unchanged unsupported result\n",r.w[3],r.w[6],r.w[7],r.w[8]);
    return kIOReturnSuccess; // Observation action only; actual setter stays unsupported.
}
bool AirportItlwm::peerCacheCopyCandidate(PeerCacheCandidateV1 *out)
{
    if (!out || !getCommandGate() || __atomic_load_n(&fAddrSyncStopping,__ATOMIC_ACQUIRE)) return false;
    const IOReturn ret=getCommandGate()->attemptAction(peerCacheCopyAction,out);
    if (ret!=kIOReturnSuccess) __atomic_add_fetch(&fPeerCacheGateMisses,1U,__ATOMIC_RELAXED);
    return ret==kIOReturnSuccess;
}
IOReturn AirportItlwm::peerCacheCopyAction(OSObject *target, void *arg, void *,void *,void *)
{
    AirportItlwm *self=OSDynamicCast(AirportItlwm,target);
    if (!self || !arg || __atomic_load_n(&self->fAddrSyncStopping,__ATOMIC_ACQUIRE) ||
        !self->fPeerCacheCandidate.sequence || !self->fSonomaAWDLInterface ||
        !self->fAddrSyncHaveCommit || self->fAddrSync.word[12]) return kIOReturnNotReady;
    ether_addr native=self->fSonomaAWDLInterface->IO80211SkywalkInterface::getSelfMacAddr();
    if (!awdlAddressEqual(&native,self->fPeerCacheCandidate.local) ||
        !awdlAddressEqual(self->fAddrSync.mac[5],self->fPeerCacheCandidate.local)) return kIOReturnNotReady;
    *static_cast<PeerCacheCandidateV1 *>(arg)=self->fPeerCacheCandidate;
    return kIOReturnSuccess;
}
