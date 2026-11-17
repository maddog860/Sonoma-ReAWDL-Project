/*
 * MAC1 S3 V47 — host-only stock TVQM admission baseline.
 * IMPORTANT: This is not a station-3 candidate authorization.
 * No firmware ownership, transmission, station removal, or DMA free
 * can be inferred from this read-only classification.
 */
#ifndef MAC1_S3_STOCK_QUEUE_SNAPSHOT_V47_HPP
#define MAC1_S3_STOCK_QUEUE_SNAPSHOT_V47_HPP
#include <stdint.h>
namespace mac1s3v47 {

enum class Finding : uint8_t {
    StopOrChangedGeneration,
    NotSubmitted,
    InvalidQueue,
    ReservedCommandQueue,
    InfrastructureTidMapped,
    PreviouslyAdopted,
    HostRingOccupied,
    HostQidNotInvalid,
    FreshHostSlotOnly
};

struct Snapshot {
    uint32_t expectedGeneration;
    uint32_t currentGeneration;
    int32_t returnedQueue;
    int32_t hostQueueCount;
    int32_t commandQueue;
    bool stopping;
    bool suspended;
    bool submitted;
    bool infraTidMapped;
    bool previouslyAdopted;
    uint32_t ringCount;
    uint32_t queued;
    bool descriptorsPresent;
    bool commandsPresent;
    bool byteCountsPresent;
    bool qidInvalid;
};

static inline Finding inspect(const Snapshot &s)
{
    if (s.stopping || s.suspended || s.expectedGeneration != s.currentGeneration)
        return Finding::StopOrChangedGeneration;
    if (!s.submitted) return Finding::NotSubmitted;
    if (s.hostQueueCount <= 0 || s.returnedQueue < 0 || s.returnedQueue >= s.hostQueueCount)
        return Finding::InvalidQueue;
    if (s.returnedQueue == s.commandQueue) return Finding::ReservedCommandQueue;
    if (s.infraTidMapped) return Finding::InfrastructureTidMapped;
    if (s.previouslyAdopted) return Finding::PreviouslyAdopted;
    if (s.ringCount != 0U || s.queued != 0U || s.descriptorsPresent ||
        s.commandsPresent || s.byteCountsPresent)
        return Finding::HostRingOccupied;
    if (!s.qidInvalid) return Finding::HostQidNotInvalid;
    return Finding::FreshHostSlotOnly;
}

static inline bool mayTransmit(Finding) { return false; }
static inline bool mayReclaimDma(Finding) { return false; }
static inline bool mayRemoveStation(Finding) { return false; }

} // namespace mac1s3v47
#endif
