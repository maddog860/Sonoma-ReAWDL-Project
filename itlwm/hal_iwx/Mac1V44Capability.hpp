#pragma once
#include <stdint.h>
/* Host-only classification of exact firmware TLV command-version records.
 * The TLV table is evidence of advertisement, NOT proof of command safety,
 * queue ownership, station retirement, DMA lifetime, or permission to TX.
 */
namespace mac1v44 {
static const uint8_t kGroup=0x05U, kOpcode=0x17U, kV3=3U;
static const uint8_t kUnknown=99U;
struct Evidence {
    uint32_t matches=0U, conflicting=0U;
    uint8_t commandVersion=kUnknown, notificationVersion=kUnknown;
    void observe(uint8_t group,uint8_t opcode,uint8_t cmdver,uint8_t notifver) {
        if(group!=kGroup || opcode!=kOpcode) return;
        if(matches==0U) {commandVersion=cmdver; notificationVersion=notifver;}
        else if(commandVersion!=cmdver || notificationVersion!=notifver) conflicting=1U;
        ++matches;
    }
    bool exactV3Advertised() const {
        return matches==1U && conflicting==0U && commandVersion==kV3;
    }
};
}
