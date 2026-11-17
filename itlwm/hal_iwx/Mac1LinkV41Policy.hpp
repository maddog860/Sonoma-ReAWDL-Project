#pragma once
#include <stdint.h>

/* V41: fail-closed LINK preflight. A matching Apple cache is correlation,
 * NOT an authenticated peer or proof of routable/working unicast. */
namespace mac1linkv41 {
enum : uint32_t {
    kNoRX = 1u, kRXAmbiguous = 2u, kStaleGeneration = 4u,
    kRXTooOld = 8u, kNoAppleCache = 16u, kCacheTooOld = 32u,
    kCacheMismatch = 64u, kBadTemplate = 128u,
    kInsufficientRX = 256u, kNoMAC1 = 512u,
    kSnapshotUnstable = 1024u, kChannelMismatch = 2048u
};
struct Evidence {
    bool rxSeen, rxAmbiguous, sameGeneration, rxFresh;
    bool appleSeen, appleFresh, appleMatches;
    bool templateReady, enoughRx, mac1Ready, snapshotStable, channelMatches;
};
inline uint32_t evidenceBlockers(const Evidence &x) {
    uint32_t b=0;
    if (!x.rxSeen) b |= kNoRX;
    if (x.rxAmbiguous) b |= kRXAmbiguous;
    if (!x.sameGeneration) b |= kStaleGeneration;
    if (!x.rxFresh) b |= kRXTooOld;
    if (!x.appleSeen) b |= kNoAppleCache;
    if (!x.appleFresh) b |= kCacheTooOld;
    if (!x.appleMatches) b |= kCacheMismatch;
    if (!x.templateReady) b |= kBadTemplate;
    if (!x.enoughRx) b |= kInsufficientRX;
    if (!x.mac1Ready) b |= kNoMAC1;
    if (!x.snapshotStable) b |= kSnapshotUnstable;
    if (!x.channelMatches) b |= kChannelMismatch;
    return b;
}
/* Firmware command requires explicit V41 opt-in AND S6 consent, no S7. */
inline bool sendAuthorized(bool linkOptIn, bool s6OptIn, bool s7OptIn,
                           bool noPriorAttempt, uint32_t evidenceMask,
                           uint32_t stockSafetyMask) {
    return linkOptIn && s6OptIn && !s7OptIn && noPriorAttempt &&
           evidenceMask == 0u && stockSafetyMask == 0u;
}
}
