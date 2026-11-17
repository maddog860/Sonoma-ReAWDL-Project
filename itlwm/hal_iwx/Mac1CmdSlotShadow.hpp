#ifndef MAC1_CMD_SLOT_SHADOW_V13_HPP
#define MAC1_CMD_SLOT_SHADOW_V13_HPP

#include <stdint.h>

// V13: observational only. No DMA ownership, locks, queue admission, or
// completion suppression. Deliberately tracks state transitions in the host,
// not a claim about what the Intel firmware has accepted or retired.
namespace mac1cmdslotshadow {

enum : uint32_t { Empty = 0, Preparing = 1, Published = 2, ResetUncertain = 3 };
// Only an observational state machine. None of these phases block real
// firmware command submission or authorize DMA retirement.
enum StopPhase : uint32_t { Running = 0, StopInProgress = 1, ResetVerified = 2 };
enum Statistic : unsigned {
    Begin = 0, BeginCollision, BeginBlockedByStop, Sent,
    PrepublishAfterReset, PrepareAborted, Completed, UnexpectedCompletion,
    CompletionDuringPreparation, StopWithPreparing, StopWithPublished,
    ConfirmedReset, InvalidIndex, RestartObserved, TotalStats
};

struct Ledger {
    static const unsigned SlotCount = 256;
    uint32_t state[SlotCount] = {};
    uint32_t count[TotalStats] = {};
    uint32_t stopPhase = Running;

    bool begin(unsigned idx) {
        if (idx >= SlotCount) { inc(InvalidIndex); return false; }
        if ((__atomic_load_n(&stopPhase, __ATOMIC_ACQUIRE) != Running)) {
            inc(BeginBlockedByStop);
            return false;
        }
        uint32_t expected = Empty;
        if (!__atomic_compare_exchange_n(&state[idx], &expected,
              uint32_t(Preparing), false, __ATOMIC_ACQ_REL,
              __ATOMIC_ACQUIRE)) {
            inc(BeginCollision);
            return false;
        }
        inc(Begin);
        if ((__atomic_load_n(&stopPhase, __ATOMIC_ACQUIRE) != Running))
            inc(BeginBlockedByStop);
        return true;
    }

    void published(unsigned idx, bool claimed) {
        if (!claimed || idx >= SlotCount) return;
        uint32_t expected = Preparing;
        if (!__atomic_compare_exchange_n(&state[idx], &expected,
              uint32_t(Published), false, __ATOMIC_ACQ_REL,
              __ATOMIC_ACQUIRE)) {
            inc(PrepublishAfterReset);
            return;
        }
        inc(Sent);
        if ((__atomic_load_n(&stopPhase, __ATOMIC_ACQUIRE) != Running))
            inc(PrepublishAfterReset);
    }

    void abandoned(unsigned idx, bool claimed) {
        if (!claimed || idx >= SlotCount) return;
        uint32_t expected = Preparing;
        if (__atomic_compare_exchange_n(&state[idx], &expected,
              uint32_t(Empty), false, __ATOMIC_ACQ_REL,
              __ATOMIC_ACQUIRE)) inc(PrepareAborted);
    }

    void completed(unsigned idx) {
        if (idx >= SlotCount) { inc(InvalidIndex); return; }
        uint32_t expected = Published;
        if (__atomic_compare_exchange_n(&state[idx], &expected,
              uint32_t(Empty), false, __ATOMIC_ACQ_REL,
              __ATOMIC_ACQUIRE)) {
            inc(Completed);
        } else if (expected == Preparing) {
            inc(CompletionDuringPreparation);
        } else {
            inc(UnexpectedCompletion);
        }
    }

    void stopStarted() {
        __atomic_store_n(&stopPhase, uint32_t(StopInProgress), __ATOMIC_RELEASE);
        for (unsigned idx = 0; idx < SlotCount; ++idx) {
            uint32_t phase = __atomic_load_n(&state[idx], __ATOMIC_ACQUIRE);
            for (;;) {
                if (phase != Preparing && phase != Published) break;
                if (__atomic_compare_exchange_n(&state[idx], &phase,
                      uint32_t(ResetUncertain), false, __ATOMIC_ACQ_REL,
                      __ATOMIC_ACQUIRE)) {
                    inc(phase == Preparing ? StopWithPreparing : StopWithPublished);
                    break;
                }
            }
        }
    }

    // Observational retirement ONLY: this confirms the hardware reset, but
    // the device is still in its shutdown path. Never re-open observations
    // until a subsequent successful iwx_start_hw().
    void resetConfirmed() {
        for (unsigned idx = 0; idx < SlotCount; ++idx)
            __atomic_store_n(&state[idx], uint32_t(Empty), __ATOMIC_RELEASE);
        inc(ConfirmedReset);
        uint32_t expected = StopInProgress;
        __atomic_compare_exchange_n(&stopPhase, &expected,
            uint32_t(ResetVerified), false, __ATOMIC_ACQ_REL,
            __ATOMIC_ACQUIRE);
    }

    // Invoked only after a successful hardware start (not on entry or
    // start failure). A failed master stop never permits this transition;
    // repeated calls during one generation are ignored.
    void hardwareReady() {
        uint32_t expected = ResetVerified;
        if (__atomic_compare_exchange_n(&stopPhase, &expected,
            uint32_t(Running), false, __ATOMIC_ACQ_REL,
            __ATOMIC_ACQUIRE)) inc(RestartObserved);
    }

    uint32_t phase() const {
        return __atomic_load_n(&stopPhase, __ATOMIC_ACQUIRE);
    }

    uint32_t stat(unsigned which) const {
        return which < TotalStats ? __atomic_load_n(&count[which], __ATOMIC_RELAXED) : 0U;
    }
private:
    void inc(unsigned which) { __atomic_fetch_add(&count[which], 1U, __ATOMIC_RELAXED); }
};
}
#endif
