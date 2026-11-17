#pragma once
#include <stdint.h>
/* V39: host-only, side-effect-free gate. This is NOT firmware confirmation. */
namespace mac1s3v39 {
struct Inputs {
    bool s6Requested;
    bool s7Requested;
    bool alreadyAttempted;
    uint32_t s6BlockMask;
    uint32_t addStaVersion;
    bool firmwareReady;
    bool commandSlotHealthy;
    bool controllerGateHealthy;
    bool tvqmHealthy;
    bool noPrivateQueueState;
    bool noOtherPeerProbe;
};
/* Separate reason bits; unlike S6's existing BlockMask these include
 * the V39 firmware-generation, command-slot and isolation requirements. */
inline uint32_t blockers(const Inputs &in)
{
    uint32_t b = 0;
    if (!in.s6Requested) b |= 1u;
    if (in.s7Requested) b |= 2u;
    if (in.alreadyAttempted) b |= 4u;
    if (in.s6BlockMask != 0) b |= 8u;
    if (in.addStaVersion != 12u) b |= 16u;
    if (!in.firmwareReady) b |= 32u;
    if (!in.commandSlotHealthy) b |= 64u;
    if (!in.controllerGateHealthy) b |= 128u;
    if (!in.tvqmHealthy) b |= 256u;
    if (!in.noPrivateQueueState) b |= 512u;
    if (!in.noOtherPeerProbe) b |= 1024u;
    return b;
}
}
