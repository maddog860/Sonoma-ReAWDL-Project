/*
 * This translation unit intentionally uses the legacy IO80211 interface
 * headers so IO80211VirtualInterface can be instantiated without mixing
 * them with the Sonoma Skywalk headers in AirportItlwmV2.cpp.
 */
#ifdef IO80211FAMILY_V2
#undef IO80211FAMILY_V2
#endif

#include "Apple80211.h"

extern "C"
IO80211VirtualInterface *
AirportItlwmCreateVirtualInterfaceBridge(
    void *controllerOpaque,
    ether_addr *ether,
    UInt role)
{
    if (!controllerOpaque || !ether)
        return NULL;

    IO80211VirtualInterface *inf = new IO80211VirtualInterface;

    if (!inf)
        return NULL;

    IO80211Controller *controller =
        (IO80211Controller *)controllerOpaque;

    if (!inf->init(
            controller,
            ether,
            role,
            role == 6 ? "awdl" : "p2p")) {
        inf->release();
        return NULL;
    }

    return inf;
}
