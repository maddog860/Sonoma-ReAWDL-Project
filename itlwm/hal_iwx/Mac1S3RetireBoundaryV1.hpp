#pragma once
#include <stdint.h>

/* A POSITIVE bus-master stop plus processor reset is a separate, mandatory
 * prerequisite and is established by the existing reset caller, NOT here.
 * This host policy excludes retirement while any experimental command/owner
 * can still be active. A response ACK alone never retires DMA.
 */
namespace mac1s3retire {
enum Reason : uint32_t {
    Ready = 0,
    NoSandbox = 1U << 0,
    WrongOwner = 1U << 1,
    CommandInFlight = 1U << 2,
    SubmitClaimHeld = 1U << 3,
    ReplySlotArmed = 1U << 4,
};
inline uint32_t blockers(bool hasSandbox, bool ownerMatches,
                         bool commandInFlight, bool submitClaimHeld,
                         bool replySlotArmed) {
    uint32_t bits = 0;
    if (!hasSandbox) bits |= NoSandbox;
    if (!ownerMatches) bits |= WrongOwner;
    if (commandInFlight) bits |= CommandInFlight;
    if (submitClaimHeld) bits |= SubmitClaimHeld;
    if (replySlotArmed) bits |= ReplySlotArmed;
    return bits;
}
inline bool mayRetireAfterConfirmedMasterStopAndReset(
    bool hasSandbox, bool ownerMatches, bool commandInFlight,
    bool submitClaimHeld, bool replySlotArmed) {
    return blockers(hasSandbox, ownerMatches, commandInFlight,
                    submitClaimHeld, replySlotArmed) == 0U;
}
} // namespace mac1s3retire
