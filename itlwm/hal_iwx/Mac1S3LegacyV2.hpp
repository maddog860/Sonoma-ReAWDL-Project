#pragma once
#include <stddef.h>
#include <stdint.h>

/* V29 host-only classifier for a PRIVATE station-3 use of the EXISTING
 * legacy SCD_QUEUE_CFG v2 ABI. Neither this file nor its caller authorizes
 * firmware submission, a QID claim, live retirement, or packet TX.
 * In particular the identical opcode used by stock must NEVER identify S3
 * without a private host-only provenance bit and a live slot claim.
 */
namespace mac1s3legacy {
static constexpr uint8_t kLongGroup = 0x01U;
static constexpr uint8_t kOpcode = 0x1dU;
static constexpr size_t kCommandBytes = 24U;
static constexpr size_t kReplyBytes = 8U;

inline bool privateCommand(bool ax210, uint32_t id, uint32_t hostFlags,
                           uint32_t privateFlag) {
    return ax210 && (hostFlags & privateFlag) != 0 && id == kOpcode;
}

inline bool expectedResponse(bool ax210, bool inFlight, bool sandboxReady,
                             bool sameGeneration, bool exactSlotClaim,
                             bool responseBufferExists, unsigned rxQid,
                             int rxIdx, unsigned cmdQid, unsigned ringCount,
                             uint8_t group, uint8_t opcode,
                             uint8_t failedMask) {
    if (!ax210 || !inFlight || !sandboxReady || !sameGeneration ||
        !exactSlotClaim || !responseBufferExists) return false;
    if (rxQid != cmdQid || rxIdx < 0 ||
        static_cast<unsigned>(rxIdx) >= ringCount) return false;
    return (group & static_cast<uint8_t>(~failedMask)) == kLongGroup &&
        opcode == kOpcode;
}

enum class Verdict : uint8_t {
    AcceptedShape = 0, TransportFailed, MissingPacket, FirmwareFailed,
    WrongCommand, WrongCommandQueue, WrongPayloadLength, StaleGeneration
};
inline Verdict classify(bool transportOk, bool hasPacket,
                        bool firmwareFailed, uint8_t group, uint8_t opcode,
                        uint8_t replyQid, uint8_t expectedCmdQid,
                        size_t payloadLength, bool sameGeneration,
                        uint8_t failedMask) {
    if (!transportOk) return Verdict::TransportFailed;
    if (!hasPacket) return Verdict::MissingPacket;
    if (firmwareFailed || (group & failedMask)) return Verdict::FirmwareFailed;
    if (group != kLongGroup || opcode != kOpcode) return Verdict::WrongCommand;
    if (replyQid != expectedCmdQid) return Verdict::WrongCommandQueue;
    if (payloadLength != kReplyBytes) return Verdict::WrongPayloadLength;
    if (!sameGeneration) return Verdict::StaleGeneration;
    return Verdict::AcceptedShape; // SHAPE ONLY; NEVER OWNERSHIP.
}
} // namespace mac1s3legacy
