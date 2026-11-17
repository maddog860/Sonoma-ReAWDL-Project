/*
 * MAC1 S3 V45: host-only, value-only ownership evidence model.
 * No firmware commands, no DMA operations, no queue registration, no TX.
 * "Candidate" means only that HOST evidence has no known conflict.
 * It is never proof of exclusive FIRMWARE ownership or safe retirement.
 */
#ifndef MAC1_S3_QUEUE_OWNER_V45_HPP
#define MAC1_S3_QUEUE_OWNER_V45_HPP

#include <stdint.h>

namespace mac1s3v45 {

enum class Decision : uint8_t {
    CandidateOnly,
    NoSubmission,
    BadCommandVersion,
    ResponseNotAccepted,
    StoppingOrGenerationChanged,
    InvalidQueue,
    StationOrTidMismatch,
    ReservedManagementQueue,
    InfraTidMapped,
    PreviouslyAdopted,
    HostSlotOccupied,
    HostSlotNotInvalid
};

struct HostRing {
    uint32_t ringCount;
    uint32_t queued;
    bool descPresent;
    bool cmdPresent;
    bool byteCountPresent;
    bool outstandingBuffer;
    bool qidInvalid;
};

struct Evidence {
    uint32_t issuedGeneration;
    uint32_t currentGeneration;
    int32_t returnedQid;
    int32_t numHostQueues;
    int32_t reservedManagementQid;
    uint8_t expectedStation;
    uint8_t stationInCommand;
    uint8_t expectedTid;
    uint8_t tidInCommand;
    uint8_t legacyCommandVersion;
    bool commandSubmitted;
    bool responseShapeAccepted;
    bool stopping;
    bool suspended;
    bool infraTidMapped;
    bool previouslyAdopted;
    HostRing ring;
};

static inline Decision inspectCandidate(const Evidence& e)
{
    if (!e.commandSubmitted) return Decision::NoSubmission;
    if (e.legacyCommandVersion != 2U) return Decision::BadCommandVersion;
    if (!e.responseShapeAccepted) return Decision::ResponseNotAccepted;
    if (e.stopping || e.suspended || e.currentGeneration != e.issuedGeneration)
        return Decision::StoppingOrGenerationChanged;
    if (e.numHostQueues <= 0 || e.returnedQid < 0 || e.returnedQid >= e.numHostQueues)
        return Decision::InvalidQueue;
    if (e.stationInCommand != e.expectedStation || e.tidInCommand != e.expectedTid)
        return Decision::StationOrTidMismatch;
    // V37's BootstrapQ2 exception must never be inherited by private S3.
    if (e.returnedQid == e.reservedManagementQid)
        return Decision::ReservedManagementQueue;
    if (e.infraTidMapped) return Decision::InfraTidMapped;
    if (e.previouslyAdopted) return Decision::PreviouslyAdopted;
    if (e.ring.ringCount != 0U || e.ring.queued != 0U || e.ring.descPresent ||
        e.ring.cmdPresent || e.ring.byteCountPresent || e.ring.outstandingBuffer)
        return Decision::HostSlotOccupied;
    if (!e.ring.qidInvalid) return Decision::HostSlotNotInvalid;
    return Decision::CandidateOnly;
}

enum class Phase : uint8_t {
    Untouched,
    Quarantined,
    CandidateQuarantined,
    PositiveResetObserved
};

struct Ledger {
    uint32_t generation;
    int32_t candidateQid;
    uint8_t station;
    uint8_t tid;
    Phase phase;
    bool commandMayHaveReachedFirmware;
    bool flushResponseObserved;
    bool resetWasPositive;

    Ledger() : generation(0U), candidateQid(-1), station(0U), tid(0U),
        phase(Phase::Untouched), commandMayHaveReachedFirmware(false),
        flushResponseObserved(false), resetWasPositive(false) {}

    // Call only when the command may have been handed to iwx_send_cmd().
    // A transport failure or malformed reply does not undo this hazard.
    bool noteSubmission(uint32_t issuedGen, uint8_t sta, uint8_t t)
    {
        // Never overwrite a possibly FW-owned quarantine with a new claim.
        if (phase != Phase::Untouched) return false;
        generation = issuedGen;
        station = sta;
        tid = t;
        candidateQid = -1;
        commandMayHaveReachedFirmware = true;
        flushResponseObserved = false;
        resetWasPositive = false;
        phase = Phase::Quarantined;
        return true;
    }

    // A clean host-slot check merely refines the quarantine's diagnostics.
    void observeResponse(const Evidence& e)
    {
        if (!commandMayHaveReachedFirmware || phase == Phase::PositiveResetObserved)
            return;
        if (generation != e.issuedGeneration || station != e.stationInCommand ||
            tid != e.tidInCommand)
            return;
        if (inspectCandidate(e) == Decision::CandidateOnly) {
            candidateQid = e.returnedQid;
            phase = Phase::CandidateQuarantined;
        }
    }

    // Station ID in a flush request, and QID+TID in a response, are not
    // sufficient proof that the FW has released its queue's DMA pointers.
    void observeFlush(uint32_t currentGen, uint8_t requestedStation,
                      uint8_t reportedTid, int32_t reportedQid, bool responseValid)
    {
        if (responseValid && commandMayHaveReachedFirmware &&
            currentGen == generation && requestedStation == station &&
            reportedTid == tid && reportedQid >= 0 &&
            reportedQid == candidateQid)
            flushResponseObserved = true;
    }

    // Observational only. Never free or reuse DMA based on this state.
    void observePositiveReset(bool positive, bool commandInFlight)
    {
        if (positive && !commandInFlight && commandMayHaveReachedFirmware) {
            resetWasPositive = true;
            phase = Phase::PositiveResetObserved;
        }
    }

    bool mayTransmit() const { return false; }
    bool mayReclaimDma() const { return false; }
    bool mayRemoveStation() const { return false; }
};

} // namespace mac1s3v45
#endif
