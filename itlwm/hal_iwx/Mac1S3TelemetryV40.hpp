#pragma once
#include <stdint.h>
/* V40: pure interpretation of an ADD_STA command result. No firmware calls. */
namespace mac1s3v40 {
enum : uint32_t {
    kAccepted = 0U,
    kTransportFailure = 1U,
    kResponseMissing = 2U,
    kFirmwareRejected = 3U,
    kGenerationChanged = 4U,
    kFirmwareNotReady = 5U,
    kUnobserved = 0xffffffffU
};
inline uint32_t maskedStatus(uint32_t status) { return status & 0xffU; }
inline uint32_t statusPresent(int transport, uint32_t status) {
    return (transport == 0 && status != kUnobserved) ? 1U : 0U;
}
inline uint32_t validationError(int transport, uint32_t status,
                                bool sameGeneration, bool firmwareReady,
                                bool notShuttingDown) {
    if (transport != 0) return kTransportFailure;
    if (status == kUnobserved) return kResponseMissing;
    if (maskedStatus(status) != 1U) return kFirmwareRejected;
    if (!sameGeneration) return kGenerationChanged;
    if (!firmwareReady || !notShuttingDown) return kFirmwareNotReady;
    return kAccepted;
}
inline uint32_t addressKind(const uint8_t *address) {
    if (!address) return 0U;
    bool allBroadcast = true;
    for (unsigned i = 0; i != 6; ++i) if (address[i] != 0xffU) allBroadcast = false;
    if (allBroadcast) return 1U;        /* broadcast template */
    if ((address[0] & 1U) == 0U) return 2U; /* individual peer */
    return 3U;                          /* multicast / unsupported */
}
}
