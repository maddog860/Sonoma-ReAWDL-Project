/* V7: a conservative host-slot collision test for stock TVQM response QIDs.
 * This header has no hardware side effects. A fresh unallocated host slot
 * has zero ring_count/queued and no DMA buffers. A firmware response is
 * never sufficient authority to replace a populated host slot.
 */
#ifndef MAC1_TVQM_HOST_SLOT_SAFETY_HPP
#define MAC1_TVQM_HOST_SLOT_SAFETY_HPP
#include <stdint.h>
namespace mac1tvqmhostslot {
static inline bool occupied(uint32_t ringCount, uint32_t queued,
                            bool descAllocated, bool cmdAllocated,
                            bool byteCountAllocated) {
    return ringCount != 0U || queued != 0U ||
           descAllocated || cmdAllocated || byteCountAllocated;
}
}
#endif
