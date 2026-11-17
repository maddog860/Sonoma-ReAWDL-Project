/* V53: host ring observation around existing stock Block Ack advancement.
 * No evidence here establishes firmware station ownership, over-air delivery,
 * or safe DMA retirement. Classification is read-only and never gates TX.
 */
#ifndef MAC1_S3_BA_ADVANCE_V53_HPP
#define MAC1_S3_BA_ADVANCE_V53_HPP
#include <stdint.h>
namespace mac1s3v53 {
enum class Finding : uint8_t {
    Unobserved = 0,
    InvalidRingCount = 1,
    RingSizeChanged = 2,
    QueueCountIncreased = 3,
    TailMoved = 4,
    QueuedDecreased = 5,
    NoVisibleChange = 6
};
struct Evidence {
    uint32_t ringCountBefore;
    uint32_t ringCountAfter;
    uint32_t tailBefore;
    uint32_t tailAfter;
    uint32_t queuedBefore;
    uint32_t queuedAfter;
};
static inline Finding inspect(const Evidence &e) {
    if (!e.ringCountBefore || !e.ringCountAfter)
        return Finding::InvalidRingCount;
    if (e.ringCountBefore != e.ringCountAfter)
        return Finding::RingSizeChanged;
    if (e.queuedAfter > e.queuedBefore)
        return Finding::QueueCountIncreased;
    if (e.tailAfter != e.tailBefore)
        return Finding::TailMoved;
    if (e.queuedAfter < e.queuedBefore)
        return Finding::QueuedDecreased;
    return Finding::NoVisibleChange;
}
static inline bool provesFirmwareStationOwnership(Finding) { return false; }
static inline bool provesAirDelivery(Finding) { return false; }
static inline bool authorizesDMAFree(Finding) { return false; }
static inline bool authorizesPrivateQueue(Finding) { return false; }
}
#endif
