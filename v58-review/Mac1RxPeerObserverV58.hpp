#ifndef MAC1_RX_PEER_OBSERVER_V58_HPP
#define MAC1_RX_PEER_OBSERVER_V58_HPP
/*
 * V58 observational core, no hardware operations, no allocations, no logging,
 * no raw peer or station identifiers persisted. Install ONLY at a confirmed
 * raw 802.11 MPDU RX point; do not use on Ethernet/decapsulated packets.
 * Separate unknown context from an actual mismatch.
 */
#include <stddef.h>
#include <stdint.h>

namespace mac1rxv58 {

struct Address {
    uint8_t bytes[6];
    bool known;
};
struct Context {
    Address localAwdl;
    Address awdlBssid;
    Address peerTransmitter;
    bool macIdKnown;
    bool isMac1;
    bool channelKnown;
    uint16_t rxChannel;
    bool peerChannelKnown;
    uint16_t peerChannel;
    bool availabilityKnown;
    bool inAvailabilityWindow;
};
struct Result {
    bool headerValid;
    bool isData;
    bool raUnicast;
    bool raKnown, raMatch;
    bool bssidKnown, bssidMatch;
    bool peerTaKnown, peerTaMatch;
    bool macIdKnown, mac1;
    bool channelComparable, peerChannelMatch;
    bool availabilityKnown, inAvailabilityWindow;
};
inline bool same(const uint8_t *a, const uint8_t *b) {
    if (!a || !b) return false;
    uint8_t d = 0;
    for (unsigned i = 0; i < 6; ++i) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}
inline Result classify(const uint8_t *frame, size_t len, const Context &ctx) {
    Result r = {};
    r.macIdKnown = ctx.macIdKnown;
    r.mac1 = ctx.isMac1 && ctx.macIdKnown;
    r.availabilityKnown = ctx.availabilityKnown;
    r.inAvailabilityWindow = ctx.inAvailabilityWindow;
    r.channelComparable = ctx.channelKnown && ctx.peerChannelKnown;
    r.peerChannelMatch = r.channelComparable && (ctx.rxChannel == ctx.peerChannel);
    if (!frame || len < 2) return r;
    const uint16_t fc = (uint16_t)frame[0] | ((uint16_t)frame[1] << 8);
    const unsigned type = (fc >> 2) & 3U;
    if (type != 0 && type != 2) return r;  // no assumptions about control frames
    if (len < 24 || ((fc & 0x0300) == 0x0300 && len < 30)) return r;
    r.headerValid = true;
    r.isData = type == 2;
    const uint8_t *ra = frame + 4;
    const uint8_t *ta = frame + 10;
    const uint8_t *bssid = nullptr;
    const bool toDs = (fc & 0x0100U) != 0;
    const bool fromDs = (fc & 0x0200U) != 0;
    if (!toDs && !fromDs) bssid = frame + 16;
    else if (toDs && !fromDs) bssid = frame + 4;
    else if (!toDs && fromDs) bssid = frame + 10;
    // Four-address frames have no unambiguous BSSID in their MAC header.
    r.raUnicast = (ra[0] & 1U) == 0;
    r.raKnown = ctx.localAwdl.known;
    r.raMatch = r.raKnown && same(ra, ctx.localAwdl.bytes);
    r.bssidKnown = ctx.awdlBssid.known && bssid;
    r.bssidMatch = r.bssidKnown && same(bssid, ctx.awdlBssid.bytes);
    r.peerTaKnown = ctx.peerTransmitter.known;
    r.peerTaMatch = r.peerTaKnown && same(ta, ctx.peerTransmitter.bytes);
    return r;
}

/* Atomic increments permit RX callbacks on multiple queues. These are only
 * observed event counts, NOT evidence that particular over-air SYNs arrived. */
struct Counters {
    volatile uint64_t rawMpduSeen;
    volatile uint64_t headerUnusable;
    volatile uint64_t dataSeen;
    volatile uint64_t dataMac1Tagged;
    volatile uint64_t dataMacIdUnknown;
    volatile uint64_t dataRaLocal;
    volatile uint64_t dataRaMismatch;
    volatile uint64_t dataRaUnknown;
    volatile uint64_t dataBssidMatch;
    volatile uint64_t dataBssidMismatch;
    volatile uint64_t dataBssidUnknown;
    volatile uint64_t dataPeerTaMatch;
    volatile uint64_t dataPeerTaMismatch;
    volatile uint64_t dataPeerTaUnknown;
    volatile uint64_t dataChannelMatch;
    volatile uint64_t dataChannelMismatch;
    volatile uint64_t dataChannelUnknown;
    volatile uint64_t dataAwActive;
    volatile uint64_t dataAwInactive;
    volatile uint64_t dataAwUnknown;
};
inline void bump(volatile uint64_t *p) { __sync_fetch_and_add(p, 1ULL); }
inline void observe(Counters &c, const uint8_t *frame, size_t len, const Context &ctx) {
    bump(&c.rawMpduSeen);
    const Result r = classify(frame, len, ctx);
    if (!r.headerValid) { bump(&c.headerUnusable); return; }
    if (!r.isData) return;
    bump(&c.dataSeen);
    if (!r.macIdKnown) bump(&c.dataMacIdUnknown);
    else if (r.mac1) bump(&c.dataMac1Tagged);
    if (!r.raKnown) bump(&c.dataRaUnknown);
    else if (r.raMatch) bump(&c.dataRaLocal);
    else bump(&c.dataRaMismatch);
    if (!r.bssidKnown) bump(&c.dataBssidUnknown);
    else if (r.bssidMatch) bump(&c.dataBssidMatch);
    else bump(&c.dataBssidMismatch);
    if (!r.peerTaKnown) bump(&c.dataPeerTaUnknown);
    else if (r.peerTaMatch) bump(&c.dataPeerTaMatch);
    else bump(&c.dataPeerTaMismatch);
    if (!r.channelComparable) bump(&c.dataChannelUnknown);
    else if (r.peerChannelMatch) bump(&c.dataChannelMatch);
    else bump(&c.dataChannelMismatch);
    if (!r.availabilityKnown) bump(&c.dataAwUnknown);
    else if (r.inAvailabilityWindow) bump(&c.dataAwActive);
    else bump(&c.dataAwInactive);
}
}
#endif
