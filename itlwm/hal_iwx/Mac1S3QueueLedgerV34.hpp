/* MAC1-S3-V34: observational, generation-qualified STOCK TXQ lifecycle.
 * No firmware commands, no DMA, no station-3 claim, no scheduling, no TX
 * authorization. An unseen QID is NEVER evidence of free firmware ownership.
 * Designed as a bounded, allocation-free Debug-only diagnostic sidecar.
 */
#ifndef MAC1_S3_QUEUE_LEDGER_V34_HPP
#define MAC1_S3_QUEUE_LEDGER_V34_HPP
#include <stdint.h>

namespace mac1s3ledger34 {

enum State : uint32_t {
    Unseen = 0U,
    StockAdopted = 1U,       /* host adopted FW queue response */
    HostDetached = 2U,       /* BA/TID mapping cleared: NOT a FW disable */
    ResetInvalidated = 3U    /* positive master stop/reset observed */
};

struct Row {
    volatile uint32_t busy;
    volatile uint32_t seq;
    volatile uint32_t seen;
    volatile uint32_t generation;
    volatile uint32_t station;
    volatile uint32_t tid;
    volatile uint32_t kind; /* 1 fixed, 2 dynamic */
    volatile uint32_t state;
};

/* Read-only per-QID details. Zero fields have no meaning unless seen=1.
 * These rows reflect accepted STOCK callback observations, not all FW queues. */
struct Detail {
    uint32_t seen;
    uint32_t generation;
    uint32_t station;
    uint32_t tid;
    uint32_t kind;
    uint32_t state;
};

struct Snapshot {
    uint32_t generation;
    uint32_t currentSeenMask;
    uint32_t currentFixedMask;
    uint32_t currentDynamicMask;
    uint32_t hostDetachedMask;
    uint32_t resetInvalidatedMask;
    uint32_t lifetimeSeenMask;
    uint32_t sameGenReassignMask;
    uint32_t adoptionCount;
    uint32_t sameOwnerRepeat;
    uint32_t sameGenReassign;
    uint32_t afterDetachReuse;
    uint32_t crossGenAdoption;
    uint32_t hostDetachCount;
    uint32_t unmatchedDetach;
    uint32_t positiveResetCount;
    uint32_t lastResetGeneration;
    uint32_t lastResetObservedMask;
    uint32_t invalidQid;
    uint32_t droppedBusy;
    uint32_t unstableSnapshot;
    static constexpr uint32_t kDetailCount = 8U; /* QIDs 0..7 */
    Detail detail[kDetailCount];
    uint32_t detailUnstableMask; /* row changed during sample; no details trusted */
    uint32_t q4State;
    uint32_t q4Generation;
    uint32_t q4Station;
    uint32_t q4Tid;
    uint32_t q4Kind;
};

struct Ledger {
    static constexpr uint32_t kMaxQid = 32U;
    Row slots[kMaxQid];
    volatile uint32_t seenEverMask;
    volatile uint32_t sameGenReassignMask;
    volatile uint32_t adoptionCount;
    volatile uint32_t sameOwnerRepeat;
    volatile uint32_t sameGenReassign;
    volatile uint32_t afterDetachReuse;
    volatile uint32_t crossGenAdoption;
    volatile uint32_t hostDetachCount;
    volatile uint32_t unmatchedDetach;
    volatile uint32_t positiveResetCount;
    volatile uint32_t lastResetGeneration;
    volatile uint32_t lastResetObservedMask;
    volatile uint32_t invalidQid;
    volatile uint32_t droppedBusy;

    static inline uint32_t get(const volatile uint32_t *p) {
        return __atomic_load_n(p, __ATOMIC_ACQUIRE);
    }
    static inline void put(volatile uint32_t *p, uint32_t value) {
        __atomic_store_n(p, value, __ATOMIC_RELEASE);
    }
    static inline void increment(volatile uint32_t *p) {
        __atomic_fetch_add(p, 1U, __ATOMIC_RELAXED);
    }
    bool lock(Row &r) {
        uint32_t expected = 0U;
        if (!__atomic_compare_exchange_n(&r.busy, &expected, 1U,
                false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            increment(&droppedBusy); // fail to observe; never block ordinary TX
            return false;
        }
        __atomic_fetch_add(&r.seq, 1U, __ATOMIC_ACQ_REL); // odd: write underway
        return true;
    }
    static void unlock(Row &r) {
        __atomic_fetch_add(&r.seq, 1U, __ATOMIC_RELEASE); // even: committed
        put(&r.busy, 0U);
    }
    void stockAdopt(uint32_t generation, int qid, int station,
                    int tid, bool dynamic) {
        if (qid < 0 || qid >= (int)kMaxQid || station < 0 || station > 255 ||
            tid < 0 || tid > 255) { increment(&invalidQid); return; }
        Row &r = slots[(unsigned)qid];
        if (!lock(r)) return;
        const uint32_t kind = dynamic ? 2U : 1U;
        if (get(&r.seen)) {
            if (get(&r.generation) == generation) {
                if (get(&r.state) == HostDetached)
                    increment(&afterDetachReuse); // NOT proven FW queue retirement
                if (get(&r.station) == (uint32_t)station &&
                    get(&r.tid) == (uint32_t)tid && get(&r.kind) == kind) {
                    increment(&sameOwnerRepeat);
                } else {
                    increment(&sameGenReassign);
                    __atomic_fetch_or(&sameGenReassignMask, 1U << qid,
                                      __ATOMIC_RELAXED);
                }
            } else {
                increment(&crossGenAdoption);
            }
        }
        put(&r.generation, generation);
        put(&r.station, (uint32_t)station);
        put(&r.tid, (uint32_t)tid);
        put(&r.kind, kind);
        put(&r.state, StockAdopted);
        put(&r.seen, 1U);
        __atomic_fetch_or(&seenEverMask, 1U << qid, __ATOMIC_RELEASE);
        increment(&adoptionCount);
        unlock(r);
    }
    void hostDetach(uint32_t generation, int qid, int station, int tid) {
        if (qid < 0 || qid >= (int)kMaxQid || station < 0 || station > 255 ||
            tid < 0 || tid > 255) { increment(&unmatchedDetach); return; }
        Row &r = slots[(unsigned)qid];
        if (!lock(r)) return;
        if (get(&r.seen) && get(&r.generation) == generation &&
            get(&r.station) == (uint32_t)station &&
            get(&r.tid) == (uint32_t)tid &&
            get(&r.state) == StockAdopted) {
            put(&r.state, HostDetached);
            increment(&hostDetachCount);
        } else {
            increment(&unmatchedDetach);
        }
        unlock(r);
    }
    /* Only call after driver has positively observed master stop AND
     * processor reset. This invalidates observed queue bookkeeping, but
     * NEVER establishes that an unobserved QID is free, and NEVER approves
     * private queue reclamation or submission. */
    void positiveMasterStopReset(uint32_t generation) {
        uint32_t observed = 0U;
        for (uint32_t q = 0U; q < kMaxQid; ++q) {
            Row &r = slots[q];
            if (!lock(r)) continue;
            if (get(&r.seen) && get(&r.generation) == generation) {
                put(&r.state, ResetInvalidated);
                observed |= 1U << q;
            }
            unlock(r);
        }
        put(&lastResetGeneration, generation);
        put(&lastResetObservedMask, observed);
        increment(&positiveResetCount);
    }
    Snapshot snapshot(uint32_t generation) const {
        Snapshot s = {};
        s.generation = generation;
        s.lifetimeSeenMask = get(&seenEverMask);
        s.sameGenReassignMask = get(&sameGenReassignMask);
        s.adoptionCount = get(&adoptionCount);
        s.sameOwnerRepeat = get(&sameOwnerRepeat);
        s.sameGenReassign = get(&sameGenReassign);
        s.afterDetachReuse = get(&afterDetachReuse);
        s.crossGenAdoption = get(&crossGenAdoption);
        s.hostDetachCount = get(&hostDetachCount);
        s.unmatchedDetach = get(&unmatchedDetach);
        s.positiveResetCount = get(&positiveResetCount);
        s.lastResetGeneration = get(&lastResetGeneration);
        s.lastResetObservedMask = get(&lastResetObservedMask);
        s.invalidQid = get(&invalidQid);
        s.droppedBusy = get(&droppedBusy);
        for (uint32_t q = 0U; q < kMaxQid; ++q) {
            const Row &r = slots[q];
            const uint32_t seq1 = get(&r.seq);
            if (seq1 & 1U) {
                ++s.unstableSnapshot;
                if (q < Snapshot::kDetailCount)
                    s.detailUnstableMask |= (1U << q);
                continue;
            }
            const uint32_t seen = get(&r.seen);
            const uint32_t gen = get(&r.generation);
            const uint32_t sta = get(&r.station);
            const uint32_t tid = get(&r.tid);
            const uint32_t kind = get(&r.kind);
            const uint32_t state = get(&r.state);
            const uint32_t seq2 = get(&r.seq);
            if (seq1 != seq2 || (seq2 & 1U)) {
                ++s.unstableSnapshot;
                if (q < Snapshot::kDetailCount)
                    s.detailUnstableMask |= (1U << q);
                continue;
            }
            if (q < Snapshot::kDetailCount && seen) {
                Detail &d = s.detail[q];
                d.seen = 1U;
                d.generation = gen;
                d.station = sta;
                d.tid = tid;
                d.kind = kind;
                d.state = state;
            }
            if (q == 4U && seen) {
                s.q4State = state;
                s.q4Generation = gen;
                s.q4Station = sta;
                s.q4Tid = tid;
                s.q4Kind = kind;
            }
            if (!seen || gen != generation) continue;
            s.currentSeenMask |= (1U << q);
            if (kind == 1U) s.currentFixedMask |= (1U << q);
            if (kind == 2U) s.currentDynamicMask |= (1U << q);
            if (state == HostDetached) s.hostDetachedMask |= (1U << q);
            if (state == ResetInvalidated) s.resetInvalidatedMask |= (1U << q);
        }
        return s;
    }
};

} // namespace mac1s3ledger34
#endif
