/* V49: read-only immediate post-V37 host ring-copy verifier.
 * This does not establish firmware queue ownership, station-3 readiness,
 * DMA retirement, or permission to transmit. No stateful actions here.
 */
#ifndef MAC1_S3_HOST_COMMIT_V49_HPP
#define MAC1_S3_HOST_COMMIT_V49_HPP
#include <stdint.h>
namespace mac1s3v49 {
enum class Finding : uint8_t {
    NotInstalled = 0, MetadataMismatch = 1,
    RingPointerMismatch = 2, HostCopyObserved = 3
};
struct Evidence {
    bool installed;
    bool qidMatches;
    uint32_t destinationCount;
    uint32_t sourceCount;
    uint32_t queued;
    bool descriptorsPresent;
    bool commandsPresent;
    bool byteCountsPresent;
    bool descriptorsMatch;
    bool commandsMatch;
    bool byteCountsMatch;
};
static inline uint32_t pointerMask(const Evidence& e) {
    return (e.descriptorsPresent && e.descriptorsMatch ? 1U : 0U) |
           (e.commandsPresent && e.commandsMatch ? 2U : 0U) |
           (e.byteCountsPresent && e.byteCountsMatch ? 4U : 0U);
}
static inline Finding inspect(const Evidence& e) {
    if (!e.installed) return Finding::NotInstalled;
    if (!e.qidMatches || e.destinationCount == 0 ||
        e.destinationCount != e.sourceCount)
        return Finding::MetadataMismatch;
    if (pointerMask(e) != 7U) return Finding::RingPointerMismatch;
    return Finding::HostCopyObserved;
}
static inline bool mayTransmit(Finding) { return false; }
static inline bool mayReclaimDma(Finding) { return false; }
static inline bool provesFirmwareOwner(Finding) { return false; }
}
#endif
