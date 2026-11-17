#pragma once
#include <stdint.h>

/* V25: a narrow, host-testable eligibility contract for the S3 v3 ADD
 * firmware response. This does not authenticate the command slot's full
 * lifetime or establish firmware TX queue ownership. In particular, the
 * firmware's failed-group flag is ignored ONLY for a positively identified
 * outstanding S3 command, never for unrelated firmware packets.
 */
namespace mac1s3v3rx {
static constexpr uint8_t kDataPathGroup = 0x05U;
static constexpr uint8_t kQueueConfigOpcode = 0x17U;
inline bool expected(bool ax210, bool s3InFlight, bool sandboxOwned,
                     bool sameGeneration, unsigned rxQid, int rxIdx,
                     unsigned cmdQid, unsigned ringCount,
                     uint8_t group, uint8_t opcode,
                     uint8_t failedMask) {
    if (!ax210 || !s3InFlight || !sandboxOwned || !sameGeneration)
        return false;
    /* High bit denotes an unsolicited notification, never a solicited
     * command response. An RX index must be validated before accessing
     * sc_cmd_resp_pkt[] or any other per-slot host array.
     */
    if (rxQid != cmdQid || rxIdx < 0 ||
        static_cast<unsigned>(rxIdx) >= ringCount) return false;
    return (group & static_cast<uint8_t>(~failedMask)) == kDataPathGroup &&
        opcode == kQueueConfigOpcode;
}
}
