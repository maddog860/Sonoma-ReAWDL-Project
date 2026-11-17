/* V51: classify read-only, stock infrastructure TID detach observations.
 * Host queue advancement is not TX success, firmware ownership,
 * DMA release, firmware station-3 ownership, or S3 TX authorization.
 */
#ifndef MAC1_S3_QUEUE_LIFECYCLE_V51_HPP
#define MAC1_S3_QUEUE_LIFECYCLE_V51_HPP
#include <stdint.h>
namespace mac1s3v51 {
enum class Finding : uint8_t {
    NoObservation = 0,
    TidInvalid = 1,
    QidInvalid = 2,
    HostRingMismatch = 3,
    MappingNotCleared = 4,
    HostTidDetached = 5
};
struct Evidence {
    bool tidValid;
    bool qidValid;
    bool ringQidMatches;
    bool mappingCleared;
};
static inline Finding inspect(const Evidence& e) {
    if (!e.tidValid) return Finding::TidInvalid;
    if (!e.qidValid) return Finding::QidInvalid;
    if (!e.ringQidMatches) return Finding::HostRingMismatch;
    if (!e.mappingCleared) return Finding::MappingNotCleared;
    return Finding::HostTidDetached;
}
static inline bool provesFirmwareTxCompletion(Finding) { return false; }
static inline bool provesDmaRetirement(Finding) { return false; }
static inline bool authorizesStation3Tx(Finding) { return false; }
}
#endif
