#ifndef AWDL_ADDRESS_SYNC_HPP
#define AWDL_ADDRESS_SYNC_HPP
#include <stdint.h>
/* Private driver diagnostic schema, not an Apple/firmware ABI. */
struct AWDLAddressSyncSnapshot { uint32_t generation; uint8_t address[6]; };
struct AWDLAddressSyncRecord { uint32_t word[24]; uint8_t mac[6][6]; };
static_assert(sizeof(AWDLAddressSyncRecord) == 132, "address record layout");
inline bool awdlAddressEqual(const void *a, const void *b) {
    const uint8_t *x = static_cast<const uint8_t *>(a);
    const uint8_t *y = static_cast<const uint8_t *>(b);
    for (unsigned i = 0; i < 6; ++i) if (x[i] != y[i]) return false;
    return true;
}
inline bool awdlAddressValid(const void *a) {
    if (!a) return false;
    const uint8_t *x = static_cast<const uint8_t *>(a);
    unsigned any = 0; for (unsigned i = 0; i < 6; ++i) any |= x[i];
    return any && !(x[0] & 1);
}
/* A completion from another request or firmware generation cannot commit. */
inline bool awdlAddressCanCommit(const void *requested, const void *bsd,
    const AWDLAddressSyncSnapshot &applied, uint32_t generation,
    uint32_t requestSequence, uint32_t currentSequence) {
    return requestSequence == currentSequence && applied.generation == generation &&
        awdlAddressValid(requested) && awdlAddressEqual(requested, bsd) &&
        awdlAddressEqual(requested, applied.address);
}
#endif
