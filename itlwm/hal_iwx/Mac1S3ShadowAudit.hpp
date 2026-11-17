/* MAC1-S3 shadow ownership audit, Debug-only, no firmware or ring operations.
 * Copyright (C) 2026. Licensed under GPL-2.0-or-later.
 * All counters are observational. Unknown != unused, and an observed
 * stock adoption is NOT proof that the firmware owner ledger is complete.
 * Builtin atomic counters allow RX and station-flush contexts to record
 * independently without borrowing an unproven workloop serialization.
 */
#ifndef MAC1_S3_SHADOW_AUDIT_HPP
#define MAC1_S3_SHADOW_AUDIT_HPP
#include <stdint.h>
namespace mac1s3 {
enum Path : uint32_t { Single = 0U, Aggregate = 1U, BlockAck = 2U, Flush = 3U };
struct Snapshot {
    uint32_t single, aggregate, blockAck, flush;
    uint32_t observedStock, ledgerUnseen, outOfRange, invalidTid;
    uint32_t lastQid, lastTid, lastGeneration, lastPath;
};
struct ShadowAudit {
    uint32_t single = 0, aggregate = 0, blockAck = 0, flush = 0;
    uint32_t observedStock = 0, ledgerUnseen = 0, outOfRange = 0, invalidTid = 0;
    uint32_t lastQid = 0, lastTid = 0, lastGeneration = 0, lastPath = 0;
    void record(Path path, uint32_t qid, uint32_t tid, uint32_t generation,
                bool inHostRange, bool stockAdoptionSeen) {
        uint32_t* counts[4] = { &single, &aggregate, &blockAck, &flush };
        if ((uint32_t)path <= (uint32_t)Flush)
            __atomic_fetch_add(counts[(uint32_t)path], 1U, __ATOMIC_RELAXED);
        if (!inHostRange) __atomic_fetch_add(&outOfRange, 1U, __ATOMIC_RELAXED);
        if (tid > 15U) __atomic_fetch_add(&invalidTid, 1U, __ATOMIC_RELAXED);
        if (stockAdoptionSeen) __atomic_fetch_add(&observedStock, 1U, __ATOMIC_RELAXED);
        else __atomic_fetch_add(&ledgerUnseen, 1U, __ATOMIC_RELAXED);
        // Latest values are independent samples, not a coherent event tuple.
        __atomic_store_n(&lastQid, qid, __ATOMIC_RELAXED);
        __atomic_store_n(&lastTid, tid, __ATOMIC_RELAXED);
        __atomic_store_n(&lastGeneration, generation, __ATOMIC_RELAXED);
        __atomic_store_n(&lastPath, (uint32_t)path, __ATOMIC_RELAXED);
    }
    Snapshot snapshot() const {
        Snapshot s = {};
        s.single = __atomic_load_n(&single, __ATOMIC_RELAXED);
        s.aggregate = __atomic_load_n(&aggregate, __ATOMIC_RELAXED);
        s.blockAck = __atomic_load_n(&blockAck, __ATOMIC_RELAXED);
        s.flush = __atomic_load_n(&flush, __ATOMIC_RELAXED);
        s.observedStock = __atomic_load_n(&observedStock, __ATOMIC_RELAXED);
        s.ledgerUnseen = __atomic_load_n(&ledgerUnseen, __ATOMIC_RELAXED);
        s.outOfRange = __atomic_load_n(&outOfRange, __ATOMIC_RELAXED);
        s.invalidTid = __atomic_load_n(&invalidTid, __ATOMIC_RELAXED);
        s.lastQid = __atomic_load_n(&lastQid, __ATOMIC_RELAXED);
        s.lastTid = __atomic_load_n(&lastTid, __ATOMIC_RELAXED);
        s.lastGeneration = __atomic_load_n(&lastGeneration, __ATOMIC_RELAXED);
        s.lastPath = __atomic_load_n(&lastPath, __ATOMIC_RELAXED);
        return s;
    }
};
} // namespace mac1s3
#endif
