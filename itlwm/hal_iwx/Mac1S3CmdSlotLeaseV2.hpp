#pragma once
#include <stdint.h>

/* V25: stock-priority admission for the experimental S3 publication.
 *
 * States: 0=idle; 1..kCount=stock producer count;
 * kIntent=S3 privately preparing, cancellable by stock;
 * kPublishing=S3 has acquired the workloop gate and is committing the
 * shared command ring. Stock retries only across this bounded critical
 * interval. No firmware wait is permitted while Publishing.
 *
 * The intent->publishing CAS MUST run as the final check under the
 * workloop gate, immediately before the first shared slot write.
 * Stock CAS intent->1 wins if it arrives before that point; S3 then
 * aborts without touching the command ring. Never force-clear a lease.
 * This is a host-side arbitration contract, NOT FW ownership proof.
 */
namespace mac1s3cmdlease {
class Lease {
    static constexpr uint32_t kIntent = 0x80000000U;
    static constexpr uint32_t kPublishing = 0x40000000U;
    static constexpr uint32_t kCount = kPublishing - 1U;
    /* Bounded kernel spin: if publication is stalled, prefer an explicit
     * admission failure to an unbounded spin under unknown IPL context.
     * This is not a final stock no-regression proof; FW sends stay gated. */
    static constexpr unsigned kStockSpins = 131072U;
    uint32_t state_ = 0;

    static void relax() {
#if defined(__x86_64__) || defined(__i386__)
        __asm__ __volatile__("pause" ::: "memory");
#else
        __atomic_signal_fence(__ATOMIC_SEQ_CST);
#endif
    }
public:
    bool enterStock() {
        uint32_t prior = __atomic_load_n(&state_, __ATOMIC_ACQUIRE);
        for (unsigned attempt = 0; attempt < kStockSpins; ++attempt) {
            if (prior == kPublishing) {
                relax();
                prior = __atomic_load_n(&state_, __ATOMIC_ACQUIRE);
                continue;
            }
            if (prior > kCount && prior != kIntent) return false;
            if (prior == kCount) return false;
            /* A stock command may revoke S3's uncommitted intent without
             * waiting for a workloop action. This prevents gate inversion. */
            const uint32_t desired = prior == kIntent ? 1U : prior + 1U;
            if (__atomic_compare_exchange_n(&state_, &prior, desired,
                                            false, __ATOMIC_ACQ_REL,
                                            __ATOMIC_ACQUIRE)) return true;
        }
        return false;
    }
    bool enterS3() {
        uint32_t expected = 0U;
        return __atomic_compare_exchange_n(&state_, &expected, kIntent,
                                           false, __ATOMIC_ACQ_REL,
                                           __ATOMIC_ACQUIRE);
    }
    /* Called ONLY inside the stop-serialized workloop callback. */
    bool beginS3Publication() {
        uint32_t expected = kIntent;
        return __atomic_compare_exchange_n(&state_, &expected, kPublishing,
                                           false, __ATOMIC_ACQ_REL,
                                           __ATOMIC_ACQUIRE);
    }
    /* Called ONLY after the MMIO doorbell is written in that callback. */
    bool finishS3Publication() {
        uint32_t expected = kPublishing;
        return __atomic_compare_exchange_n(&state_, &expected, 0U,
                                           false, __ATOMIC_ACQ_REL,
                                           __ATOMIC_ACQUIRE);
    }
    void leaveStock() {
        __atomic_fetch_sub(&state_, 1U, __ATOMIC_RELEASE);
    }
    /* Cancel only our own uncommitted intent. Stock may have revoked it;
     * never erase an active stock count or a completed publication. */
    void leaveS3() {
        uint32_t expected = kIntent;
        (void)__atomic_compare_exchange_n(&state_, &expected, 0U,
                                          false, __ATOMIC_ACQ_REL,
                                          __ATOMIC_ACQUIRE);
    }
    bool exclusivelyS3() const {
        return __atomic_load_n(&state_, __ATOMIC_ACQUIRE) == kIntent;
    }
    uint32_t snapshot() const {
        return __atomic_load_n(&state_, __ATOMIC_ACQUIRE);
    }
};
} // namespace
