#ifndef MAC1_COMMAND_PREPUB_AUDIT_HPP
#define MAC1_COMMAND_PREPUB_AUDIT_HPP

#include <stdint.h>

/* V9: pure, host-testable snapshot classification. OBSERVATION ONLY.
 * This does not synchronize the test with reset and does not authorize
 * command submission or any station-3 firmware operations. */
namespace mac1cmdprepub {
enum Flag : unsigned {
    EpochShift = 1U << 0,
    Suspended = 1U << 1,
    ResetActive = 1U << 2,
    ShuttingDown = 1U << 3
};
static inline unsigned classify(uint32_t startEpoch, uint32_t observedEpoch,
                                bool suspended, bool resetActive,
                                bool shuttingDown)
{
    return (startEpoch != observedEpoch ? EpochShift : 0U) |
           (suspended ? Suspended : 0U) |
           (resetActive ? ResetActive : 0U) |
           (shuttingDown ? ShuttingDown : 0U);
}
}

#endif /* MAC1_COMMAND_PREPUB_AUDIT_HPP */
