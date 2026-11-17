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

    IO80211Controller *controller =
        (IO80211Controller *)controllerOpaque;

    IO80211VirtualInterface *inf = NULL;

    if (role == APPLE80211_VIF_AWDL) {

        /*
         * Sonoma adaptation of KGP frontend architecture.
         *
         * Sonoma does not register IO80211P2PInterface, but it
         * does register IO80211VirtualInterface and already has
         * its P2P data-path manager alive.
         *
         * Keep KGP's AWDL role/name and lifecycle while using the
         * Sonoma-available virtual-interface frontend.
         */
        controller->setProperty(
            "AIRPLAYKGPFrontendSonomaVIFAttempted",
            (unsigned long long)1,
            8
        );

        inf = new IO80211VirtualInterface;

        controller->setProperty(
            "AIRPLAYKGPFrontendSonomaVIFAllocated",
            (unsigned long long)(inf != NULL ? 1 : 0),
            8
        );

    } else {

        inf = new IO80211VirtualInterface;
    }

    if (!inf)
        return NULL;

    if (!inf->init(
            controller,
            ether,
            role,
            role == APPLE80211_VIF_AWDL ? "awdl" : "p2p")) {
        inf->release();
        return NULL;
    }

    if (role == APPLE80211_VIF_AWDL) {
        inf->setProperty(
            "AIRPLAYKGPFrontendRole6Object",
            (unsigned long long)1,
            8
        );
    }

    return inf;
}
