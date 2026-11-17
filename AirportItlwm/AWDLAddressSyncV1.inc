/* AWDL-ADDRSYNC-V1. Included only by Sonoma V2's controller translation unit.
 * Existing firmware MAC follower remains the sole radio update path.
 * All native-cache work occurs under the controller gate. Worker attempts do
 * not block, and no firmware command or NIC lock is held across event 59.
 * The 132-byte record is one coherent diagnostic publication (little endian).
 * words: magic,version,size,sequence,phase,requestCalls,polls,notifyCalls,
 * fwGeneration,lastErr,committedSequence,committedGeneration,pending,
 * gateMisses,duplicateSkips,postRevalidationFailures; 16..23 reserved.
 * mac slots: requested,BSD,MAC1-submitted,selfBefore,selfAfter,lastNotified.
 */
struct AWDLAddrSyncRequest { ether_addr address; SInt32 result; };

extern "C" bool airplayAwdlExperimentsEnabled(void);
extern "C" bool AirportItlwmAWDLCurrentAddr(uint8_t *);

bool AirportItlwm::awdlAddressSyncEnabled()
{
    static int disabled = -1;
    if (disabled < 0) {
        int value = 0;
        disabled = PE_parse_boot_argn("-awdladdrsyncoff", &value, sizeof(value)) ? 1 : 0;
    }
    ItlIwx *iwx = OSDynamicCast(ItlIwx, fHalService);
    return airplayAwdlExperimentsEnabled() && !disabled && iwx &&
        iwx->com.sc_device_family == IWX_DEVICE_FAMILY_AX210;
}

void AirportItlwm::awdlAddressSyncPublish()
{
    fAddrSync.word[0] = 0x31534141; // AAS1
    fAddrSync.word[1] = 1;
    fAddrSync.word[2] = sizeof(fAddrSync);
    fAddrSync.word[13] = __atomic_load_n(&fAddrSyncGateMisses, __ATOMIC_RELAXED);
    OSData *record = OSData::withBytes(&fAddrSync, sizeof(fAddrSync));
    if (record) { setProperty("AIRPLAYAddrSyncRecordV1", record); record->release(); }
    setProperty("AIRPLAYAddrSyncSequence", (unsigned long long)fAddrSync.word[3], 32);
    setProperty("AIRPLAYAddrSyncPhase", (unsigned long long)fAddrSync.word[4], 32);
    setProperty("AIRPLAYAddrSyncPending", (unsigned long long)fAddrSync.word[12], 32);
    setProperty("AIRPLAYAddrSyncNotifyCalls", (unsigned long long)fAddrSync.word[7], 32);
}

IOReturn AirportItlwm::awdlAddressSyncDrainAction(OSObject *, void *, void *, void *, void *)
{ return kIOReturnSuccess; }

IOReturn AirportItlwm::awdlAddressSyncRequestAction(OSObject *target, void *arg,
    void *, void *, void *)
{
    AirportItlwm *self = OSDynamicCast(AirportItlwm, target);
    if (!self || __atomic_load_n(&self->fAddrSyncStopping, __ATOMIC_ACQUIRE))
        return kIOReturnNotReady;
    AWDLAddrSyncRequest *request = static_cast<AWDLAddrSyncRequest *>(arg);
    if (!request || !awdlAddressValid(&request->address)) return kIOReturnBadArgument;
    const void *address = &request->address;
    AWDLAddressSyncRecord &r = self->fAddrSync;
    ++r.word[5];
    if (!self->fAddrSyncHaveRequest || !awdlAddressEqual(r.mac[0], address)) {
        ++r.word[3];
        memcpy(r.mac[0], address, 6);
        self->fAddrSyncHaveRequest = true;
        r.word[4] = 1; r.word[12] = 1; r.word[9] = 0;
    }
    self->awdlAddressSyncPublish();
    const UInt32 requestSequence = r.word[3];
    awdlAddressSyncPollAction(target, nullptr, nullptr, nullptr, nullptr);
    request->result = requestSequence == r.word[3] &&
        awdlAddressEqual(r.mac[0], address) && r.word[4] == 3 && !r.word[12] && !r.word[9]
        ? 0 : EINPROGRESS;
    return kIOReturnSuccess;
}

void AirportItlwm::awdlAddressSyncSet(AirportItlwmAWDLInterface *interface,
    ether_addr *address)
{
    if (!awdlAddressValid(address) || !getCommandGate() ||
        __atomic_load_n(&fAddrSyncStopping, __ATOMIC_ACQUIRE)) return;
    ether_addr copy = *address;
    getCommandGate()->runAction(awdlAddressSyncSetAction, interface, &copy);
}

IOReturn AirportItlwm::awdlAddressSyncSetAction(OSObject *target, void *vif, void *arg,
    void *, void *)
{
    AirportItlwm *self = OSDynamicCast(AirportItlwm, target);
    if (!self || __atomic_load_n(&self->fAddrSyncStopping, __ATOMIC_ACQUIRE) ||
        vif != self->fSonomaAWDLInterface || !awdlAddressValid(arg))
        return kIOReturnNotReady;
    /* Reentrant native callback records the request on this same gate. Both
     * native forwarding and ifnet_set_lladdr finish before reconciliation. */
    self->fSonomaAWDLInterface->addressSyncSetHardwareOriginal(static_cast<ether_addr *>(arg));
    return awdlAddressSyncPollAction(target, nullptr, nullptr, nullptr, nullptr);
}

void AirportItlwm::awdlAddressSyncPoll()
{
    if (!awdlAddressSyncEnabled() || !getCommandGate() ||
        __atomic_load_n(&fAddrSyncStopping, __ATOMIC_ACQUIRE)) return;
    if (getCommandGate()->attemptAction(awdlAddressSyncPollAction) != kIOReturnSuccess)
        __atomic_add_fetch(&fAddrSyncGateMisses, 1U, __ATOMIC_RELAXED);
}

extern "C" void AirportItlwmAWDLAddressReconcile(void *controller)
{
    AirportItlwm *self = OSDynamicCast(AirportItlwm, static_cast<IOEthernetController *>(controller));
    if (self) self->awdlAddressSyncPoll();
}

IOReturn AirportItlwm::awdlAddressSyncPollAction(OSObject *target, void *, void *, void *, void *)
{
    AirportItlwm *self = OSDynamicCast(AirportItlwm, target);
    if (!self || __atomic_load_n(&self->fAddrSyncStopping, __ATOMIC_ACQUIRE))
        return kIOReturnNotReady;
    if (self->fAddrSyncNotifying) return kIOReturnSuccess;
    AirportItlwmAWDLInterface *vif = self->fSonomaAWDLInterface;
    ItlIwx *iwx = OSDynamicCast(ItlIwx, self->fHalService);
    if (!vif || !iwx) return kIOReturnNotReady;
    AWDLAddressSyncRecord &r = self->fAddrSync;
    ++r.word[6];
    uint8_t bsd[6] = {};
    AWDLAddressSyncSnapshot applied = {};
    if (!AirportItlwmAWDLCurrentAddr(bsd) || !awdlAddressValid(bsd)) {
        r.word[4] = 1; r.word[9] = EADDRNOTAVAIL;
        self->awdlAddressSyncPublish(); return kIOReturnSuccess;
    }
    memcpy(r.mac[1], bsd, 6);
    /* A prior BSD-only change is observable even if no new callback occurred. */
    if (!self->fAddrSyncHaveRequest) {
        ++r.word[3]; memcpy(r.mac[0], bsd, 6);
        self->fAddrSyncHaveRequest = true; r.word[12] = 1;
    }
    const UInt32 sequence = r.word[3];
    int err = iwx->awdlAddressSyncSnapshot(&applied);
    r.word[8] = UInt32(iwx->com.sc_generation);
    if (!err) memcpy(r.mac[2], applied.address, 6);
    if (err || !awdlAddressCanCommit(r.mac[0], bsd, applied,
        r.word[8], sequence, r.word[3])) {
        r.word[4] = 2; r.word[9] = err ? err : EAGAIN; r.word[12] = 1;
        self->awdlAddressSyncPublish(); return kIOReturnSuccess;
    }
    ether_addr before = vif->IO80211SkywalkInterface::getSelfMacAddr();
    memcpy(r.mac[3], &before, 6);
    if (self->fAddrSyncHaveCommit && r.word[10] == sequence &&
        r.word[11] == applied.generation && awdlAddressEqual(r.mac[5], bsd) &&
        awdlAddressEqual(&before, bsd)) {
        ++r.word[14]; r.word[4] = 3; r.word[9] = 0; r.word[12] = 0;
        self->awdlAddressSyncPublish(); return kIOReturnSuccess;
    }
    /* Refresh everything just before changing native state. No queued pointer
     * to caller memory, no private Apple field write, no new radio command. */
    uint8_t latest[6] = {};
    AWDLAddressSyncSnapshot fresh = {};
    if (!AirportItlwmAWDLCurrentAddr(latest) || iwx->awdlAddressSyncSnapshot(&fresh) ||
        !awdlAddressCanCommit(r.mac[0], latest, fresh,
            UInt32(iwx->com.sc_generation), sequence, r.word[3]) ||
        fresh.generation != applied.generation || !awdlAddressEqual(latest, bsd)) {
        r.word[4] = 4; r.word[9] = EAGAIN; r.word[12] = 1;
        self->awdlAddressSyncPublish(); return kIOReturnSuccess;
    }
    self->fAddrSyncNotifying = true;
    struct ClearFlag { bool &flag; ~ClearFlag() { flag = false; } };
    ClearFlag notificationScope{self->fAddrSyncNotifying};
    ether_addr desired = {}; memcpy(&desired, bsd, 6);
    vif->IO80211SkywalkInterface::setSelfMacAddr(&desired);
    ether_addr after = vif->IO80211SkywalkInterface::getSelfMacAddr();
    memcpy(r.mac[4], &after, 6);
    if (!awdlAddressEqual(&after, bsd)) {
        r.word[4] = 7; r.word[9] = EIO; r.word[12] = 1;
        self->awdlAddressSyncPublish(); return kIOReturnSuccess;
    }
    ++r.word[7];
    /* Native postMessage consumes these six copied bytes synchronously via
     * reportDataPathEvents; its void return is not evidence of peer-manager
     * receipt or a radio ACK. Validate manager self address in next-boot logs. */
    vif->IO80211VirtualInterface::postMessage(
        APPLE80211_M_LINK_ADDRESS_CHANGED, &desired, sizeof(desired), false);
    memcpy(r.mac[5], &desired, 6);
    r.word[11] = applied.generation;
    if (sequence != r.word[3] || !AirportItlwmAWDLCurrentAddr(latest) ||
        iwx->awdlAddressSyncSnapshot(&fresh) ||
        !awdlAddressCanCommit(r.mac[0], latest, fresh,
            UInt32(iwx->com.sc_generation), sequence, r.word[3]) ||
        fresh.generation != applied.generation) {
        ++r.word[15]; r.word[4] = 8; r.word[9] = EAGAIN; r.word[12] = 1;
    } else {
        self->fAddrSyncHaveCommit = true;
        r.word[10] = sequence; r.word[4] = 3; r.word[9] = 0; r.word[12] = 0;
        IOLog("AIRPLAY ADDRSYNC-V1: seq=%u generation=%u native-cache aligned; event59 issued addr=%02x:%02x:%02x:%02x:%02x:%02x\n",
            sequence, applied.generation, bsd[0], bsd[1], bsd[2], bsd[3], bsd[4], bsd[5]);
    }
    self->awdlAddressSyncPublish();
    return kIOReturnSuccess;
}
