/* MAC1-S3 V3 model port, isolated Debug-only integration.
 * Host-side state machine only. No firmware commands, DMA operations or
 * changes to txq[]/reclamation. Mutations require serialized driver context.
 * Actual live kext only invokes resolve() in this stage.
 */
#ifndef MAC1_S3_OWNER_REGISTRY_HPP
#define MAC1_S3_OWNER_REGISTRY_HPP
#include <stdint.h>
#include <stddef.h>

namespace mac1s3registry {
enum class Owner : uint8_t { Unknown, Stock, Station3, Conflict };
enum class Phase : uint8_t {
    Empty, Prepared, Submitted, Registered, Active,
    Draining, Retiring, Quarantined, Retired
};
enum class Result : uint8_t { Ok, Reject, Quarantine };
enum class Path : uint8_t { Single, BlockAck, Flush };
struct Completion { uint16_t qid, tid; uint32_t frames; };
struct Lease { uint64_t token; uint32_t generation; Path path; };
struct Resolution { Owner owner; };

class Registry {
public:
    enum { kMaxQid = 32, kMaxLeases = 16 };
    /* Host-side epoch transition only. Never infer these proofs from gen++.
     * Not wired to any live driver callback in this revision.
     */
    /* V82: non-authorizing registry epoch rejection reasons. All reads must
     * occur in the same serialized driver context as other registry calls.
     * Zero means only that the CURRENT registry's beginVerifiedEpoch() guard
     * would accept these supplied booleans. It is not proof that the booleans
     * accurately describe hardware, callback quiescence or DMA ownership.
     * This method never advances the epoch, claims a QID or releases DMA.
     * Bits: 0=invalid gen, 1=no master reset, 2=commands not quiescent,
     * 3=callbacks not quiescent, 4=repeated epoch, 5=lifecycle busy,
     * 6=DMA may be referenced, 7=private claimed, 8=outstanding TX,
     * 9=in-flight completions, 10=live lease. */
    uint32_t verifiedEpochRejectMask(uint32_t nextGen,
                                    bool masterResetVerified,
                                    bool commandsQuiescent,
                                    bool callbacksQuiescent) const {
        uint32_t mask = 0U;
        if (!nextGen) mask |= 1U << 0;
        if (!masterResetVerified) mask |= 1U << 1;
        if (!commandsQuiescent) mask |= 1U << 2;
        if (!callbacksQuiescent) mask |= 1U << 3;
        if (epoch_ && nextGen == epoch_) mask |= 1U << 4;
        if (phase_ != Phase::Empty && phase_ != Phase::Retired)
            mask |= 1U << 5;
        if (mayReferenceDma_) mask |= 1U << 6;
        if (claimed_) mask |= 1U << 7;
        if (outstanding_) mask |= 1U << 8;
        if (inFlight_) mask |= 1U << 9;
        for (unsigned i = 0; i < kMaxLeases; ++i)
            if (leases_[i].token) { mask |= 1U << 10; break; }
        return mask;
    }

    bool beginVerifiedEpoch(uint32_t nextGen, bool masterResetVerified,
                            bool commandsQuiescent, bool callbacksQuiescent) {
        if (!nextGen || !masterResetVerified || !commandsQuiescent ||
            !callbacksQuiescent || (epoch_ && nextGen == epoch_) ||
            (phase_ != Phase::Empty && phase_ != Phase::Retired) ||
            mayReferenceDma_ || claimed_ || outstanding_ || inFlight_)
            return false;

        for (unsigned i = 0; i < kMaxLeases; ++i)
            if (leases_[i].token) return false;

        for (unsigned i = 0; i < kMaxQid; ++i) {
            stock_[i] = false;
            stockGen_[i] = 0;
        }

        gen_ = 0;
        tid_ = 0;
        qid_ = 0;
        epoch_ = nextGen;
        phase_ = Phase::Empty;
        return true;
    }

    /* Bookkeeping of a known stock adoption. Never infer free from not seen. */
    bool claimStock(uint16_t q, uint32_t gen) {
        if (!gen || (epoch_ && gen != epoch_) ||
            q >= kMaxQid || stock_[q] || privateOwned(q)) return false;
        if (!epoch_) epoch_ = gen;
        stock_[q] = true; stockGen_[q] = gen; return true;
    }
    bool prepare(uint32_t gen, uint16_t tid) {
        if (phase_ != Phase::Empty || !gen || tid > 15 ||
            (epoch_ && gen != epoch_)) return false;
        if (!epoch_) epoch_ = gen;
        gen_ = gen; tid_ = tid; phase_ = Phase::Prepared; return true;
    }
    /* Called BEFORE issuing any firmware command that may refer to DMA. */
    /* A ring/descriptor allocation that never reached firmware is locally
     * disposable. An allocation after markSubmitted is NOT abortable here. */
    bool abortPrepared(uint32_t gen) {
        if (phase_ != Phase::Prepared || gen != gen_ || mayReferenceDma_) return false;
        phase_ = Phase::Empty; gen_ = 0; tid_ = 0; return true;
    }
    bool markSubmitted(uint32_t gen) {
        if (phase_ != Phase::Prepared || gen != gen_) return false;
        mayReferenceDma_ = true; phase_ = Phase::Submitted; return true;
    }
    /* Explicit positive proof required. Ledger absence alone is not proof. */
    bool registerQueue(uint16_t q, uint32_t gen, bool exclusiveOwnershipVerified) {
        if (phase_ != Phase::Submitted) return false;
        /* After submission, malformed QIDs and stale generations are uncertain
         * FW outcomes, not safe opportunities for a second allocation.
         */
        if (gen != gen_ || q >= kMaxQid) { uncertain(); return false; }
        if (stock_[q] || claimed_ || !exclusiveOwnershipVerified) {
            uncertain(); return false;
        }
        qid_ = q; claimed_ = true; phase_ = Phase::Registered; return true;
    }
    bool activate(uint32_t gen, bool firmwareStationConfirmed, bool queueConfirmed) {
        if (phase_ != Phase::Registered || gen != gen_ ||
            !firmwareStationConfirmed || !queueConfirmed) return false;
        phase_ = Phase::Active; return true;
    }
    bool submit(uint32_t gen) {
        if (phase_ != Phase::Active || gen != gen_ || outstanding_ == UINT32_MAX) return false;
        ++outstanding_; return true;
    }
    Resolution resolve(uint16_t q, uint32_t gen, bool externallyObservedStock = false) const {
        if (q >= kMaxQid) return {};
        const bool stock = externallyObservedStock || (stock_[q] && stockGen_[q] == gen);
        const bool own = privateOwned(q) && gen_ == gen && phase_ != Phase::Retired;
        const bool completionEligible = phase_ == Phase::Active ||
            phase_ == Phase::Draining || phase_ == Phase::Retiring;
        /* A pending or quarantined claim is NOT a usable TX completion owner. */
        if (own && (stock || !completionEligible)) return {Owner::Conflict};
        if (own) return {Owner::Station3};
        if (stock) return {Owner::Stock};
        return {};
    }
    Result acquire(uint16_t q, uint32_t gen, uint16_t tid, Path path, Lease& lease) {
        lease = {};
        const Owner owner = resolve(q,gen).owner;
        if (owner == Owner::Stock || owner == Owner::Unknown) return Result::Reject;
        if (owner == Owner::Conflict) { uncertain(); return Result::Quarantine; }
        if (!mayFinish() || tid != tid_ || !outstanding_) {
            uncertain(); return Result::Quarantine;
        }
        for (unsigned i=0; i<kMaxLeases; ++i) {
            if (!leases_[i].token) {
                if (nextToken_ == 0U) nextToken_ = 1U;
                if (nextToken_ == UINT64_MAX) { uncertain(); return Result::Quarantine; }
                leases_[i] = {nextToken_++, gen, path};
                ++inFlight_; lease = {leases_[i].token,gen,path}; return Result::Ok;
            }
        }
        uncertain(); return Result::Quarantine;
    }
    Result finish(const Lease& lease, uint32_t frames) {
        const int i=leaseIndex(lease);
        if (i < 0) return Result::Reject;
        if (lease.generation != gen_ || !mayFinish() || frames > outstanding_) {
            uncertain(); release(static_cast<unsigned>(i)); return Result::Quarantine;
        }
        outstanding_ -= frames; release(static_cast<unsigned>(i)); return Result::Ok;
    }
    Result blockAck(const Lease& lease, const Completion* entries, size_t n) {
        const int i=leaseIndex(lease);
        if (i < 0 || lease.path != Path::BlockAck) return Result::Reject;
        if (!entries || n == 0 || n > 16 || lease.generation != gen_ || !mayFinish()) {
            uncertain(); release(static_cast<unsigned>(i)); return Result::Quarantine;
        }
        uint64_t total=0;
        for (size_t j=0;j<n;++j) {
            if (entries[j].qid != qid_ || entries[j].tid != tid_ || !entries[j].frames) {
                uncertain(); release(static_cast<unsigned>(i)); return Result::Quarantine;
            }
            total += entries[j].frames;
        }
        if (total > outstanding_) { uncertain(); release(static_cast<unsigned>(i)); return Result::Quarantine; }
        outstanding_ -= static_cast<uint32_t>(total);
        release(static_cast<unsigned>(i)); return Result::Ok;
    }
    bool beginDrain(uint32_t gen) {
        if (phase_ != Phase::Active || gen != gen_) return false;
        phase_ = Phase::Draining; return true;
    }
    bool beginRetire(uint32_t gen, bool drainAck, bool flushBoundaryVerified) {
        if (phase_ != Phase::Draining || gen != gen_) return false;
        if (!drainAck || !flushBoundaryVerified || outstanding_ || inFlight_) {
            uncertain(); return false;
        }
        phase_ = Phase::Retiring; return true;
    }
    /* Live retirement is deliberately NOT used by the integration patch.
     * Before enabling it, separate queue-disable proof from DMA-safe proof.
     */
    bool finishRetire(uint32_t gen, bool disabled, bool dmaQuiescent, bool callbacksQuiescent) {
        if (phase_ != Phase::Retiring || gen != gen_) return false;
        if (!disabled || !dmaQuiescent || !callbacksQuiescent || outstanding_ || inFlight_) {
            uncertain(); return false;
        }
        claimed_ = false; mayReferenceDma_ = false; phase_ = Phase::Retired; return true;
    }
    /* Reset-only alternative. Caller must verify *positive* master stop,
     * processor reset, no in-flight command, and callback quiescence.
     * This only updates MODEL state; it never releases DMA.
     */
    bool resetRetired(uint32_t gen, bool positiveMasterStopAndReset,
                      bool commandQuiescent, bool callbacksQuiescent) {
        if (gen != gen_ || !mayReferenceDma_ ||
            !positiveMasterStopAndReset || !commandQuiescent ||
            !callbacksQuiescent || inFlight_) return false;
        claimed_ = false; mayReferenceDma_ = false;
        phase_ = Phase::Retired; return true;
    }
    void uncertain() { if (phase_ != Phase::Retired) phase_ = Phase::Quarantined; }
    Phase phase() const { return phase_; }
    uint32_t generation() const { return gen_; }
    uint32_t outstanding() const { return outstanding_; }
    uint32_t inFlight() const { return inFlight_; }
    bool privateOwned(uint16_t qid) const { return claimed_ && qid_ == qid; }
    bool mayReferenceDma() const { return mayReferenceDma_; }
private:
    struct ActiveLease { uint64_t token; uint32_t gen; Path path; };
    /* No default member initializers: global instance is statically zeroed.
     * No C++ static constructors run at kernel load time for this object. */
    bool stock_[kMaxQid];
    uint32_t stockGen_[kMaxQid];
    ActiveLease leases_[kMaxLeases];
    uint16_t qid_, tid_;
    uint32_t gen_, epoch_, outstanding_, inFlight_;
    uint64_t nextToken_;
    bool claimed_, mayReferenceDma_;
    Phase phase_;
    int leaseIndex(const Lease& lease) const {
        if (!lease.token) return -1;
        for (unsigned i=0; i<kMaxLeases; ++i)
            if (leases_[i].token == lease.token && leases_[i].gen == lease.generation &&
                leases_[i].path == lease.path) return static_cast<int>(i);
        return -1;
    }
    bool mayFinish() const {
        return phase_ == Phase::Active || phase_ == Phase::Draining || phase_ == Phase::Retiring;
    }
    void release(unsigned i) { leases_[i] = {}; --inFlight_; }
};

struct AuditSnapshot { uint32_t stock, unknown, privateQid, conflict, invalid; };
struct Audit {
    uint32_t stock, unknown, privateQid, conflict, invalid;
    void record(Owner owner, bool validHostQid) {
        if (!validHostQid) { __atomic_fetch_add(&invalid,1U,__ATOMIC_RELAXED); return; }
        uint32_t* p = owner == Owner::Stock ? &stock :
            owner == Owner::Station3 ? &privateQid :
            owner == Owner::Conflict ? &conflict : &unknown;
        __atomic_fetch_add(p,1U,__ATOMIC_RELAXED);
    }
    AuditSnapshot snapshot() const {
        return {__atomic_load_n(&stock,__ATOMIC_RELAXED),
                __atomic_load_n(&unknown,__ATOMIC_RELAXED),
                __atomic_load_n(&privateQid,__ATOMIC_RELAXED),
                __atomic_load_n(&conflict,__ATOMIC_RELAXED),
                __atomic_load_n(&invalid,__ATOMIC_RELAXED)};
    }
};
}
#endif
