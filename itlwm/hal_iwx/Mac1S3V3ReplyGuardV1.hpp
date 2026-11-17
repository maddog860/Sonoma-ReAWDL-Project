#pragma once
#include <stdint.h>
#include <stddef.h>

/* Strict identity validation for a station-3 SCD_QUEUE_CONFIG_CMD v3 ADD
 * reply. This is not a firmware ownership or DMA-retirement verdict.
 * Header fields are passed in host byte order by the caller.
 */
namespace mac1s3v3reply {
enum class Verdict : uint32_t {
    AcceptedShape = 0,       // shape only, NEVER queue ownership
    TransportFailed = 1,
    MissingPacket = 2,
    FirmwareFailed = 3,
    WrongCommand = 4,
    WrongCommandQueue = 5,
    WrongPayloadLength = 6,
    StaleGeneration = 7,
};
static constexpr uint8_t kGroup = 0x05;
static constexpr uint8_t kOpcode = 0x17;
inline Verdict classify(bool transportOk, bool hasPacket,
                        bool firmwareFailed,
                        uint8_t group, uint8_t opcode, uint8_t replyQid,
                        uint8_t expectedCmdQid, size_t payloadLength,
                        size_t expectedLength, bool sameGeneration) {
    if (!transportOk) return Verdict::TransportFailed;
    if (!hasPacket) return Verdict::MissingPacket;
    if (firmwareFailed) return Verdict::FirmwareFailed;
    if (group != kGroup || opcode != kOpcode) return Verdict::WrongCommand;
    // In Intel RX headers, bit 7 of QID indicates unsolicited notification.
    // Requiring the exact command queue excludes both notifications and
    // responses assigned to some other host queue.
    if (replyQid != expectedCmdQid) return Verdict::WrongCommandQueue;
    if (payloadLength != expectedLength) return Verdict::WrongPayloadLength;
    if (!sameGeneration) return Verdict::StaleGeneration;
    return Verdict::AcceptedShape;
}
}
