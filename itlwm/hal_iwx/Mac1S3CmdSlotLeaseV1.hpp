#pragma once
#include <stdint.h>

/* V23: a short prepare/doorbell lease, NOT firmware ownership.
 * Stock producers may run concurrently as before; the experimental S3
 * producer requires an exclusive window. The lease ends before the
 * synchronous firmware response wait. Never reset a live lease on stop.
 */
namespace mac1s3cmdlease {
class Lease {
    static constexpr uint32_t kExclusive = 0x80000000U;
    static constexpr uint32_t kCount = ~kExclusive;
    uint32_t state_ = 0;
public:
    bool enterStock() {
        uint32_t prior = __atomic_load_n(&state_, __ATOMIC_ACQUIRE);
        for (;;) {
            if ((prior & kExclusive) || (prior & kCount) == kCount)
                return false;
            if (__atomic_compare_exchange_n(&state_, &prior, prior + 1U,
                                            false, __ATOMIC_ACQ_REL,
                                            __ATOMIC_ACQUIRE)) return true;
        }
    }
    bool enterS3() {
        uint32_t expected = 0;
        return __atomic_compare_exchange_n(&state_, &expected, kExclusive,
                                           false, __ATOMIC_ACQ_REL,
                                           __ATOMIC_ACQUIRE);
    }
    void leaveStock() { __atomic_fetch_sub(&state_, 1U, __ATOMIC_RELEASE); }
    void leaveS3() { __atomic_store_n(&state_, 0U, __ATOMIC_RELEASE); }
    bool exclusivelyS3() const {
        return __atomic_load_n(&state_, __ATOMIC_ACQUIRE) == kExclusive;
    }
    uint32_t snapshot() const {
        return __atomic_load_n(&state_, __ATOMIC_ACQUIRE);
    }
};
} // namespace
