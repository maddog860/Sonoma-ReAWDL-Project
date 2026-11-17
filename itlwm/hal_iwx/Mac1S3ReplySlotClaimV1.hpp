#pragma once
#include <stdint.h>

/* Host-side reply/command-slot binding for the *single* S3 v3 ADD attempt.
 * No firmware nonce exists in the current packet ABI: matching a generation,
 * command queue and slot is necessary but is NOT proof of a response's serial
 * authenticity, command lifetime, DMA quiescence or exclusive FW queue owner.
 * Do not use this class to authorize an experimental firmware write.
 *
 * The S3 publisher installs the claim immediately before touching the shared
 * command slot, still under the stop-serialized workloop gate. The RX path
 * verifies it before interpreting a v3 queue response. Stop invalidates the
 * claim without releasing any DMA. Timeout/completion clears only our token.
 */
namespace mac1s3replyslot {
class Claim {
    /* bits 55:24=generation, 23:16=command QID, 15:0=slot+1.
     * 0 means unarmed. Fail closed if a field cannot be encoded exactly. */
    uint64_t word_ = 0;
    static uint64_t encode(uint32_t generation, unsigned qid, unsigned idx) {
        if (qid > 255U || idx >= 65535U) return 0;
        return (static_cast<uint64_t>(generation) << 24) |
               (static_cast<uint64_t>(qid) << 16) |
               static_cast<uint64_t>(idx + 1U);
    }
public:
    bool arm(uint32_t generation, unsigned qid, unsigned idx) {
        const uint64_t next = encode(generation, qid, idx);
        if (!next) return false;
        uint64_t empty = 0;
        return __atomic_compare_exchange_n(&word_, &empty, next, false,
                                           __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    }
    bool matches(uint32_t generation, unsigned qid, unsigned idx) const {
        const uint64_t wanted = encode(generation, qid, idx);
        return wanted != 0 &&
               __atomic_load_n(&word_, __ATOMIC_ACQUIRE) == wanted;
    }
    bool clearMine(uint32_t generation, unsigned qid, unsigned idx) {
        uint64_t expected = encode(generation, qid, idx);
        if (!expected) return false;
        return __atomic_compare_exchange_n(&word_, &expected, uint64_t(0),
                                           false, __ATOMIC_ACQ_REL,
                                           __ATOMIC_ACQUIRE);
    }
    void noteStop() {
        __atomic_store_n(&word_, uint64_t(0), __ATOMIC_RELEASE);
    }
    bool armed() const {
        return __atomic_load_n(&word_, __ATOMIC_ACQUIRE) != 0;
    }
};
} // namespace mac1s3replyslot
