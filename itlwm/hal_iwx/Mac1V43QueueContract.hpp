#ifndef MAC1_V43_QUEUE_CONTRACT_HPP
#define MAC1_V43_QUEUE_CONTRACT_HPP
#include <stdint.h>
/* Fail-closed preflight policy. This never authorizes DMA, firmware queue
 * enable, host ring commit, or transmission. A firmware-returned QID remains
 * unknown even if its host slot looks vacant. */
namespace mac1v43 {
enum Reason : uint32_t {
    kNoLinkAdd        = 1U << 0,
    kStaleGeneration  = 1U << 1,
    kWrongCommandAbi  = 1U << 2,
    kFirmwareNotReady = 1U << 3,
    kCommandUnhealthy = 1U << 4,
    kLedgerUnstable   = 1U << 5,
    kOtherProbe       = 1U << 6,
    kNoVerifiedOwner  = 1U << 7,
    kNoDmaLifetime    = 1U << 8,
    kNoRetirement     = 1U << 9,
    kNoCompletion     = 1U << 10,
    kNoAuthentication = 1U << 11,
    kPrivateTxOff     = 1U << 12,
};
struct Evidence {
    bool linkAdded, generationMatches, commandVersion2, firmwareReady;
    bool commandHealthy, ledgerCoherent, noOtherPrivateProbe;
    bool ownerVerified, dmaLifetimeVerified, retirementVerified;
    bool completionVerified, peerAuthenticated;
};
static inline uint32_t blockers(const Evidence &e) {
    uint32_t b = kPrivateTxOff; // Hard off for V43 regardless of Evidence.
    if (!e.linkAdded) b |= kNoLinkAdd;
    if (!e.generationMatches) b |= kStaleGeneration;
    if (!e.commandVersion2) b |= kWrongCommandAbi;
    if (!e.firmwareReady) b |= kFirmwareNotReady;
    if (!e.commandHealthy) b |= kCommandUnhealthy;
    if (!e.ledgerCoherent) b |= kLedgerUnstable;
    if (!e.noOtherPrivateProbe) b |= kOtherProbe;
    if (!e.ownerVerified) b |= kNoVerifiedOwner;
    if (!e.dmaLifetimeVerified) b |= kNoDmaLifetime;
    if (!e.retirementVerified) b |= kNoRetirement;
    if (!e.completionVerified) b |= kNoCompletion;
    if (!e.peerAuthenticated) b |= kNoAuthentication;
    return b;
}
static inline bool abiPrepared(const Evidence &e) {
    return e.linkAdded && e.generationMatches && e.commandVersion2 &&
           e.firmwareReady && e.commandHealthy && e.ledgerCoherent &&
           e.noOtherPrivateProbe;
}
static inline bool txPermitted(const Evidence &e) {
    return blockers(e) == 0U;  // Unreachable in V43 by construction.
}
} // namespace mac1v43
#endif
