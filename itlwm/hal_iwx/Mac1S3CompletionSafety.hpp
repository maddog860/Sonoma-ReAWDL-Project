/* S3 completion dispatch V5: pure host-side safety decision.
 * Never dispatch a completion to a private ring here; that requires
 * a separately reviewed owner-specific handler and token/lease validation.
 * Only normal stock QIDs are permitted through stock reclamation.
 */
#ifndef MAC1_S3_COMPLETION_SAFETY_HPP
#define MAC1_S3_COMPLETION_SAFETY_HPP
#include <stdint.h>
namespace mac1s3completion {
enum class Decision : uint8_t { Stock, InvalidQid, HoldPrivate };
inline Decision classify(uint32_t reportedQid, uint32_t hostQueueCount,
                         bool privateClaim) {
    if (reportedQid >= hostQueueCount) return Decision::InvalidQid;
    if (privateClaim) return Decision::HoldPrivate;
    return Decision::Stock;
}
}
#endif
