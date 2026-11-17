/* V55: host-only stock Q2-Q4 flush response / BA teardown consistency.
 * Does NOT prove firmware station ownership, TX delivery, or DMA retirement.
 */
#ifndef MAC1_S3_FLUSH_DETACH_V55_HPP
#define MAC1_S3_FLUSH_DETACH_V55_HPP
#include <stdint.h>
#include "Mac1S3MapLineageV54.hpp"
namespace mac1s3v55 {
enum class FlushFinding : uint8_t {
    Unobserved=0, OutOfScope=1, StationMismatch=2, InvalidHostQid=3,
    InvalidHostTid=4, RingMismatch=5, CurrentMapMismatch=6,
    NoHistory=7, DifferentGeneration=8, DifferentTid=9,
    HostFlushConsistent=10
};
enum class DetachFinding : uint8_t {
    Unobserved=0, InvalidHostQid=1, RingMismatch=2,
    MappingNotCleared=3, NoHistory=4, DifferentGeneration=5,
    DifferentTid=6, HostDetachConsistent=7
};
static inline FlushFinding inspectFlush(bool trackedQid, bool stationIsInfra,
        bool qidValid, bool tidValid, bool ringMatches, bool mapMatches,
        mac1s3v54::Finding history) {
    if (!trackedQid) return FlushFinding::OutOfScope;
    if (!stationIsInfra) return FlushFinding::StationMismatch;
    if (!qidValid) return FlushFinding::InvalidHostQid;
    if (!tidValid) return FlushFinding::InvalidHostTid;
    if (!ringMatches) return FlushFinding::RingMismatch;
    if (!mapMatches) return FlushFinding::CurrentMapMismatch;
    if (history == mac1s3v54::Finding::NoHistoricalMap)
        return FlushFinding::NoHistory;
    if (history == mac1s3v54::Finding::DifferentGeneration)
        return FlushFinding::DifferentGeneration;
    if (history == mac1s3v54::Finding::DifferentTid)
        return FlushFinding::DifferentTid;
    return history == mac1s3v54::Finding::HistoricalMapMatches ?
        FlushFinding::HostFlushConsistent : FlushFinding::NoHistory;
}
static inline DetachFinding inspectDetach(bool qidValid, bool ringMatches,
        bool mapCleared, mac1s3v54::Finding history) {
    if (!qidValid) return DetachFinding::InvalidHostQid;
    if (!ringMatches) return DetachFinding::RingMismatch;
    if (!mapCleared) return DetachFinding::MappingNotCleared;
    if (history == mac1s3v54::Finding::NoHistoricalMap)
        return DetachFinding::NoHistory;
    if (history == mac1s3v54::Finding::DifferentGeneration)
        return DetachFinding::DifferentGeneration;
    if (history == mac1s3v54::Finding::DifferentTid)
        return DetachFinding::DifferentTid;
    return history == mac1s3v54::Finding::HistoricalMapMatches ?
        DetachFinding::HostDetachConsistent : DetachFinding::NoHistory;
}
static inline bool provesFirmwareOwnership(FlushFinding) { return false; }
static inline bool provesDMARetirement(FlushFinding) { return false; }
static inline bool provesAirDelivery(DetachFinding) { return false; }
static inline bool authorizesPrivateTransmission(DetachFinding) { return false; }
}
#endif
