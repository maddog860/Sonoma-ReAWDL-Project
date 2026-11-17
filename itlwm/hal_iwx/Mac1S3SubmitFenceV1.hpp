#pragma once
/* MAC1-S3 V31: stop-serialized, recovery-aware one-shot submission fence.
 * A host stop closes admission synchronously, before workloop dispatch.
 * Reopening requires a completed AX210 master-stop/reset AND the existing
 * PC1 recoverAction checks (firmware generation, command readiness, TX state).
 * This fence is NOT a firmware queue owner, command-slot nonce, DMA retirement
 * proof, or permission for AWDL packet rerouting.
 */
#include <stdint.h>

namespace mac1s3submitfence {
class Fence {
    /* Bits 0..1 = stop/claim, remaining bits = monotonic stop-request serial.
     * Packing serial + stop in ONE CAS makes external stop and reopen race-safe.
     */
    uint64_t serialFlags_ = 0;
    uint64_t provenStopSerial_ = 0;
    uint32_t provenResetEpoch_ = 0;
    uintptr_t provenOwner_ = 0;
    uint32_t reopenCount_ = 0;
    uint32_t reopenRefusals_ = 0;
    enum : uint64_t { kFlags = 3ULL, kStep = 4ULL };
public:
    enum : uint32_t { kStop = 1U, kClaim = 2U };
    bool claim() {
        uint64_t expected = __atomic_load_n(&serialFlags_, __ATOMIC_ACQUIRE);
        if ((expected & kFlags) != 0U) return false;
        return __atomic_compare_exchange_n(&serialFlags_, &expected,
            expected | kClaim, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    }
    void noteStop() {
        uint64_t cur = __atomic_load_n(&serialFlags_, __ATOMIC_ACQUIRE);
        for (;;) {
            /* Saturate on serial exhaustion rather than wrap/re-authorize. */
            const uint64_t next = (cur >> 2) == (UINT64_MAX >> 2) ?
                (cur | kStop) :
                (((cur & ~kFlags) + kStep) | (cur & kClaim) | kStop);
            if (__atomic_compare_exchange_n(&serialFlags_, &cur, next,
                    false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return;
        }
    }
    uint64_t stopSerial() const {
        return __atomic_load_n(&serialFlags_, __ATOMIC_ACQUIRE) >> 2;
    }
    void resetVerified(const void *owner, uint64_t handledSerial,
                       uint32_t resetEpoch) {
        /* Called only on the main workloop AFTER positive master-stop/reset.
         * The serial was captured on entering the gate, never at reset end:
         * an external stop posted during reset must remain pending. */
        __atomic_store_n(&provenOwner_, reinterpret_cast<uintptr_t>(owner),
                         __ATOMIC_RELEASE);
        __atomic_store_n(&provenResetEpoch_, resetEpoch, __ATOMIC_RELEASE);
        __atomic_store_n(&provenStopSerial_, handledSerial, __ATOMIC_RELEASE);
    }
    bool recoverAfterPC1(const void *owner, uint32_t resetEpoch) {
        /* Caller holds the main workloop gate after *all* PC1 recovery checks.
         * No outstanding private DMA/response claim may be present. */
        const uint64_t verified = __atomic_load_n(&provenStopSerial_,
                                                   __ATOMIC_ACQUIRE);
        const uintptr_t proofOwner = __atomic_load_n(&provenOwner_,
                                                      __ATOMIC_ACQUIRE);
        const uint32_t proofEpoch = __atomic_load_n(&provenResetEpoch_,
                                                    __ATOMIC_ACQUIRE);
        uint64_t current = __atomic_load_n(&serialFlags_, __ATOMIC_ACQUIRE);
        if (!owner || verified == 0 || verified == (UINT64_MAX >> 2) ||
            proofOwner != reinterpret_cast<uintptr_t>(owner) ||
            resetEpoch == 0 || proofEpoch != resetEpoch ||
            (current >> 2) != verified || (current & kFlags) != kStop) {
            __atomic_fetch_add(&reopenRefusals_, 1U, __ATOMIC_RELAXED);
            return false;
        }
        /* A new stop in the gap changes the serial and fails this CAS.
         * A stop AFTER the CAS re-closes the gate atomically. */
        const bool reopened = __atomic_compare_exchange_n(&serialFlags_,
            &current, current & ~uint64_t(kStop), false,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
        __atomic_fetch_add(reopened ? &reopenCount_ : &reopenRefusals_,
                           1U, __ATOMIC_RELAXED);
        return reopened;
    }
    bool maySend() const {
        return (__atomic_load_n(&serialFlags_, __ATOMIC_ACQUIRE) & kFlags) == kClaim;
    }
    void endClaim() {
        __atomic_fetch_and(&serialFlags_, ~uint64_t(kClaim), __ATOMIC_ACQ_REL);
    }
    uint32_t state() const {
        return (uint32_t)(__atomic_load_n(&serialFlags_, __ATOMIC_ACQUIRE) & kFlags);
    }
    uint64_t verifiedSerial() const {
        return __atomic_load_n(&provenStopSerial_, __ATOMIC_ACQUIRE);
    }
    uint32_t reopens() const {
        return __atomic_load_n(&reopenCount_, __ATOMIC_ACQUIRE);
    }
    uint32_t refusals() const {
        return __atomic_load_n(&reopenRefusals_, __ATOMIC_ACQUIRE);
    }
    bool stopped() const { return (state() & kStop) != 0U; }
    bool claimed() const { return (state() & kClaim) != 0U; }
};
} // namespace mac1s3submitfence
