/* V50 — observational post-allocation host TID->QID bookkeeping.
 * This is never firmware ownership, S3 authorization, DMA retirement,
 * permission to transmit, or permission to reroute TX.
 */
#ifndef MAC1_S3_TID_MAPPING_V50_HPP
#define MAC1_S3_TID_MAPPING_V50_HPP
#include <stdint.h>
namespace mac1s3v50 {
enum class Finding : uint8_t {
    NoObservation = 0,
    TidOutOfRange = 1,
    QidOutOfRange = 2,
    MappingMismatch = 3,
    RingQidMismatch = 4,
    HostRingIncomplete = 5,
    HostMappingObserved = 6
};
struct Evidence {
    bool tidValid;
    bool qidValid;
    bool mappingMatches;
    bool ringQidMatches;
    uint32_t ringCount;
    uint32_t queued;
    uint32_t pointerMask;
};
static inline Finding inspect(const Evidence& e) {
    if (!e.tidValid) return Finding::TidOutOfRange;
    if (!e.qidValid) return Finding::QidOutOfRange;
    if (!e.mappingMatches) return Finding::MappingMismatch;
    if (!e.ringQidMatches) return Finding::RingQidMismatch;
    if (!e.ringCount || e.queued > e.ringCount || e.pointerMask != 7U)
        return Finding::HostRingIncomplete;
    return Finding::HostMappingObserved;
}
static inline bool provesFirmwareOwnership(Finding) { return false; }
static inline bool permitsStation3Tx(Finding) { return false; }
static inline bool permitsDmaRetirement(Finding) { return false; }
}
#endif
