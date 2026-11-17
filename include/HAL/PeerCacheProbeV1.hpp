#ifndef PEER_CACHE_PROBE_V1_HPP
#define PEER_CACHE_PROBE_V1_HPP
#include <stdint.h>
#include <stddef.h>
#include <HAL/AWDLAddressSync.hpp>
/* Driver-owned wire records. No changes to Apple or firmware ABI classes. */
struct PeerCacheRequestV1 { uint32_t w[24]; uint8_t local[6], peer[6], prefix[64]; };
struct PeerCacheCandidateV1 { uint32_t sequence, generation, seconds; uint8_t peer[6], local[6]; };
struct PeerCacheNativeV1 { uint32_t w[16]; uint8_t umi[64]; };
struct PeerStationProbeV1 { uint32_t w[40]; uint8_t peer[6], local[6], add[48], remove[4]; };
static_assert(sizeof(PeerCacheRequestV1)==172, "request schema");
static_assert(sizeof(PeerCacheCandidateV1)==24, "candidate schema");
static_assert(sizeof(PeerCacheNativeV1)==128, "native gate schema");
static_assert(sizeof(PeerStationProbeV1)==224, "probe schema");
enum PeerPrefixError { PC_NULL=1, PC_SHORT=2, PC_VERSION=4, PC_OPCODE=8,
    PC_ADDRESS=16, PC_HT_IE=32, PC_VHT_IE=64, PC_SELF=128 };
inline uint32_t pcLE32(const uint8_t *p) {
    return uint32_t(p[0]) | uint32_t(p[1])<<8 | uint32_t(p[2])<<16 | uint32_t(p[3])<<24;
}
inline uint32_t pcParsePrefix(const uint8_t *p, size_t n) {
    if (!p) return PC_NULL;
    if (n<4) return PC_SHORT;
    if (pcLE32(p)!=1) return PC_VERSION;
    if (n<64) return PC_SHORT;
    uint32_t errors=0, op=pcLE32(p+4);
    if (op!=0 && op!=2 && op!=6) errors |= PC_OPCODE;
    if (!awdlAddressValid(p+8)) errors |= PC_ADDRESS;
    if (op!=2) {
        unsigned ht=0;for(unsigned i=16;i<44;++i)ht|=p[i];
        if (ht && (p[16]!=45 || p[17]!=26)) errors|=PC_HT_IE;
        if (p[45] && (p[46]!=191 || p[47]!=12)) errors|=PC_VHT_IE;
    }
    return errors;
}
inline bool pcCandidateMatches(const PeerCacheCandidateV1 &a,
    const PeerCacheCandidateV1 &b) {
    return a.sequence && a.sequence==b.sequence && a.generation==b.generation &&
        awdlAddressEqual(a.peer,b.peer) && awdlAddressEqual(a.local,b.local);
}
inline bool pcAddConfirmed(int error, bool responsePresent, uint32_t status,
    uint32_t success, uint32_t generationBefore, uint32_t generationAfter) {
    return !error && responsePresent && (status & 0xffU)==success && generationBefore==generationAfter;
}
#endif
