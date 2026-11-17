/* V6: persistent, fail-closed host-side guard for the stock TVQM scratch ring.
 * The driver owns the DMA memory; this guard owns no DMA and never submits
 * firmware commands. Trivially zero-initialized at load time (Ready == 0).
 * An uncertain command pins the scratch until positive master stop + reset.
 */
#ifndef MAC1_TVQM_SCRATCH_SAFETY_HPP
#define MAC1_TVQM_SCRATCH_SAFETY_HPP
#include <stdint.h>
namespace mac1tvqmscratch {
enum : uint32_t { Ready=0, Preparing=1, Submitted=2, Quarantined=3, ResetClaimed=4 };
struct Guard {
    uint32_t state_;
    const void *owner_;
    uint32_t generation_;
    uint32_t blocked_, uncertain_, retired_;

    uint32_t state() const { return __atomic_load_n(&state_, __ATOMIC_ACQUIRE); }
    uint32_t blocked() const { return __atomic_load_n(&blocked_, __ATOMIC_RELAXED); }
    uint32_t uncertain() const { return __atomic_load_n(&uncertain_, __ATOMIC_RELAXED); }
    uint32_t retired() const { return __atomic_load_n(&retired_, __ATOMIC_RELAXED); }

    bool matches(const void *owner, uint32_t generation) const {
        return __atomic_load_n(&owner_, __ATOMIC_ACQUIRE) == owner &&
               __atomic_load_n(&generation_, __ATOMIC_ACQUIRE) == generation;
    }
    bool begin(const void *owner, uint32_t generation) {
        if (!owner) return false;  // firmware generation zero is valid
        uint32_t expected=Ready;
        if (!__atomic_compare_exchange_n(&state_, &expected, Preparing, false,
                                         __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            __atomic_add_fetch(&blocked_, 1U, __ATOMIC_RELAXED);
            return false;
        }
        __atomic_store_n(&generation_, generation, __ATOMIC_RELEASE);
        __atomic_store_n(&owner_, owner, __ATOMIC_RELEASE);
        return true;
    }
    bool markSubmitted(const void *owner, uint32_t generation) {
        if (state() != Preparing || !matches(owner, generation)) return false;
        uint32_t expected=Preparing;
        return __atomic_compare_exchange_n(&state_, &expected, Submitted, false,
                                           __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    }
    bool abortPrepared(const void *owner, uint32_t generation) {
        if (state()!=Preparing || !matches(owner, generation)) return false;
        __atomic_store_n(&owner_, nullptr, __ATOMIC_RELEASE);
        __atomic_store_n(&generation_, 0U, __ATOMIC_RELEASE);
        __atomic_store_n(&state_, Ready, __ATOMIC_RELEASE);
        return true;
    }
    bool quarantine(const void *owner, uint32_t generation) {
        if (state()!=Submitted || !matches(owner, generation)) return false;
        uint32_t expected=Submitted;
        if (!__atomic_compare_exchange_n(&state_, &expected, Quarantined, false,
                                         __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return false;
        __atomic_add_fetch(&uncertain_, 1U, __ATOMIC_RELAXED);
        return true;
    }
    bool adopt(const void *owner, uint32_t generation) {
        if (state()!=Submitted || !matches(owner, generation)) return false;
        __atomic_store_n(&owner_, nullptr, __ATOMIC_RELEASE);
        __atomic_store_n(&generation_, 0U, __ATOMIC_RELEASE);
        __atomic_store_n(&state_, Ready, __ATOMIC_RELEASE);
        return true;
    }
    /* Caller must establish the positive bus master stop + processor reset.
     * A pending firmware call (Submitted) NEVER authorizes retirement.
     */
    bool claimReset(const void *owner, bool positiveMasterStopAndReset) {
        if (!positiveMasterStopAndReset || state()!=Quarantined ||
            __atomic_load_n(&owner_, __ATOMIC_ACQUIRE) != owner) return false;
        uint32_t expected=Quarantined;
        return __atomic_compare_exchange_n(&state_, &expected, ResetClaimed, false,
                                           __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    }
    bool finishReset(const void *owner) {
        if (state()!=ResetClaimed ||
            __atomic_load_n(&owner_, __ATOMIC_ACQUIRE) != owner) return false;
        __atomic_store_n(&owner_, nullptr, __ATOMIC_RELEASE);
        __atomic_store_n(&generation_, 0U, __ATOMIC_RELEASE);
        __atomic_add_fetch(&retired_, 1U, __ATOMIC_RELAXED);
        __atomic_store_n(&state_, Ready, __ATOMIC_RELEASE);
        return true;
    }
};
}
#endif
