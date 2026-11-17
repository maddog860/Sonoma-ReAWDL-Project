/* S3 V8: pure AX210 host-ring commit admission policy.
 * Call exclusively within the existing main workloop gate. It does not
 * prove that the FW-provided QID is exclusively owned by the host.
 */
#ifndef MAC1_TVQM_COMMIT_SAFETY_HPP
#define MAC1_TVQM_COMMIT_SAFETY_HPP
#include <stdint.h>
namespace mac1tvqmcommit {
enum Decision : uint8_t {
    Permit = 0,
    StopOrGenerationChanged = 1,
    ScratchNotSubmitted = 2,
    SlotOccupied = 3
};
static inline Decision decide(bool shuttingDown, bool suspended,
                              bool generationChanged, bool scratchSubmitted,
                              bool slotOccupied) {
    if (shuttingDown || suspended || generationChanged)
        return StopOrGenerationChanged;
    if (!scratchSubmitted) return ScratchNotSubmitted;
    if (slotOccupied) return SlotOccupied;
    return Permit;
}
}
#endif
