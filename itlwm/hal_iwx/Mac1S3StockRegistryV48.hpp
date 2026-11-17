/* V48: report existing V37 stock admission in IORegistry.
 * Host-only diagnostic classification, never FW ownership proof.
 * This header grants no TX, DMA reclamation, or station removal.
 */
#ifndef MAC1_S3_STOCK_REGISTRY_V48_HPP
#define MAC1_S3_STOCK_REGISTRY_V48_HPP
#include <stdint.h>
namespace mac1s3v48 {
enum class Kind : uint8_t { None = 0, FreshHostOnly = 1, BootstrapHostOnly = 2 };
struct Input {
    uint32_t expectedGeneration;
    uint32_t currentGeneration;
    int32_t returnedQueue;
    int32_t hostQueueCount;
    uint32_t v37Decision;
    bool stopping;
    bool suspended;
};
/* V37::Fresh=0 and V37::BootstrapQ2=1; all other decisions fail closed. */
static inline Kind classify(const Input& x) {
    if (x.stopping || x.suspended || x.expectedGeneration != x.currentGeneration)
        return Kind::None;
    if (x.hostQueueCount <= 0 || x.returnedQueue < 0 ||
        x.returnedQueue >= x.hostQueueCount)
        return Kind::None;
    if (x.v37Decision == 0U) return Kind::FreshHostOnly;
    if (x.v37Decision == 1U) return Kind::BootstrapHostOnly;
    return Kind::None;
}
static inline bool mayTransmit(Kind) { return false; }
static inline bool mayReclaimDma(Kind) { return false; }
static inline bool mayRemoveStation(Kind) { return false; }
}
#endif
