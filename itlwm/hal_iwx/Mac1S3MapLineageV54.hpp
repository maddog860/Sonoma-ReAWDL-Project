/* V54: historical host QID/TID map vs subsequent stock BA completion.
 * HOST-only telemetry: a matching historical map never proves firmware
 * station ownership, successful delivery, or safe DMA reclamation.
 */
#ifndef MAC1_S3_MAP_LINEAGE_V54_HPP
#define MAC1_S3_MAP_LINEAGE_V54_HPP
#include <stdint.h>
namespace mac1s3v54 {
enum class Finding : uint8_t {
    Unobserved = 0,
    NoHistoricalMap = 1,
    DifferentGeneration = 2,
    DifferentTid = 3,
    HistoricalMapMatches = 4
};
/* Single atomic word per QID. Do not mistake this history for an active owner. */
static inline uint64_t encode(uint32_t generation, uint32_t tid) {
    return (1ULL << 63) | ((uint64_t)generation << 8) | (uint64_t)(tid & 255U);
}
static inline Finding inspect(uint64_t history, uint32_t generation, uint32_t tid) {
    if (!(history & (1ULL << 63))) return Finding::NoHistoricalMap;
    if ((uint32_t)((history >> 8) & 0xffffffffULL) != generation)
        return Finding::DifferentGeneration;
    if ((uint32_t)(history & 255ULL) != tid)
        return Finding::DifferentTid;
    return Finding::HistoricalMapMatches;
}
static inline bool provesFirmwareStationOwnership(Finding) { return false; }
static inline bool provesAirDelivery(Finding) { return false; }
static inline bool authorizesPrivateQueue(Finding) { return false; }
static inline bool authorizesDMAFree(Finding) { return false; }
}
#endif
