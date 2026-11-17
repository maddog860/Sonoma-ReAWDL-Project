/* V42: host-only reasoning over firmware/host evidence, NEVER an allocator. */
#ifndef MAC1_V42_OWNER_POLICY_HPP
#define MAC1_V42_OWNER_POLICY_HPP
#include <stdint.h>
namespace mac1v42 {
enum ReadinessBlocker : uint32_t {
    LinkNotAccepted = 1U << 0,
    StationRetirementUnverified = 1U << 1,
    QueueNotRequested = 1U << 2,
    FirmwareQidUnverified = 1U << 3,
    DmaLifetimeUnverified = 1U << 4,
    CompletionOwnerUnverified = 1U << 5,
    PeerNotAuthenticated = 1U << 6,
    TxHardDisabled = 1U << 7,
};
struct Evidence {
    bool linkAccepted;
    bool stationRetiredIndependently;
    bool queueCommandIssued;
    bool fwQidOwnerVerified;
    bool dmaLifetimeVerified;
    bool completionOwnerVerified;
    bool peerAuthenticated;
};
static inline uint32_t blockers(const Evidence &e) {
    uint32_t m = TxHardDisabled;  // V42 cannot authorize private TX by design.
    if (!e.linkAccepted) m |= LinkNotAccepted;
    if (!e.stationRetiredIndependently) m |= StationRetirementUnverified;
    if (!e.queueCommandIssued) m |= QueueNotRequested;
    if (!e.fwQidOwnerVerified) m |= FirmwareQidUnverified;
    if (!e.dmaLifetimeVerified) m |= DmaLifetimeUnverified;
    if (!e.completionOwnerVerified) m |= CompletionOwnerUnverified;
    if (!e.peerAuthenticated) m |= PeerNotAuthenticated;
    return m;
}
static inline bool txPermitted(const Evidence&) { return false; }
static inline bool queueOwnerVerifiedFromMissingObservation(bool) { return false; }
}
#endif
