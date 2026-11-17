/*
 * MAC1 S3 V46: read-only S7 firmware reply observation adapter.
 * This NEVER grants TX, station removal, or DMA reclamation.
 * Earlier S7 host-slot classification remains authoritative for existing diagnostics;
 * a clean host candidate is NOT proof of firmware queue ownership.
 */
#ifndef MAC1_S3_QUEUE_OBSERVE_V46_HPP
#define MAC1_S3_QUEUE_OBSERVE_V46_HPP
#include <stdint.h>

namespace mac1s3v46 {

enum class Finding : uint8_t {
    NotSubmitted = 0,
    BadLegacyVersion = 1,
    CommandStationOrTidMismatch = 2,
    ReplyNotAccepted = 3,
    StoppingOrEpochChanged = 4,
    ReturnedQidOutOfRange = 5,
    ReservedQueue = 6,
    ExistingS7Conflict = 7,
    HostCandidateStillUnverified = 8
};

struct Snapshot {
    uint32_t issuedGeneration;
    uint32_t currentGeneration;
    int32_t returnedQid;
    int32_t hostQueueCount;
    int32_t commandQueueQid;
    int32_t managementQueueQid;
    int32_t firstDataQid;
    uint32_t existingS7Audit;
    uint8_t legacyCommandVersion;
    uint8_t commandSta;
    uint8_t expectedSta;
    uint8_t commandTid;
    uint8_t expectedTid;
    bool commandActuallySubmitted;
    bool acceptedResponseShape;
    bool shutdown;
    bool suspended;
};

static inline Finding inspect(const Snapshot& x)
{
    if (!x.commandActuallySubmitted) return Finding::NotSubmitted;
    if (x.legacyCommandVersion != 2U) return Finding::BadLegacyVersion;
    if (x.commandSta != x.expectedSta || x.commandTid != x.expectedTid)
        return Finding::CommandStationOrTidMismatch;
    if (!x.acceptedResponseShape) return Finding::ReplyNotAccepted;
    if (x.shutdown || x.suspended || x.issuedGeneration != x.currentGeneration)
        return Finding::StoppingOrEpochChanged;
    if (x.hostQueueCount <= 0 || x.returnedQid < 0 || x.returnedQid >= x.hostQueueCount)
        return Finding::ReturnedQidOutOfRange;
    if (x.returnedQid == x.commandQueueQid ||
        x.returnedQid == x.managementQueueQid ||
        x.returnedQid == x.firstDataQid)
        return Finding::ReservedQueue;
    // S7's existing classification value 7 means no *known host* collision.
    // Preserve that evidence without pretending the FW relinquished any owner.
    if (x.existingS7Audit != 7U) return Finding::ExistingS7Conflict;
    return Finding::HostCandidateStillUnverified;
}

// No caller can turn this observational finding into a write authority.
static inline bool mayTransmit(Finding) { return false; }
static inline bool mayReclaimDma(Finding) { return false; }
static inline bool mayRemoveStation(Finding) { return false; }
}
#endif
