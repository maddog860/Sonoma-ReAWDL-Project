//
//  AirportItlwmSkywalkInterface.cpp
//  AirportItlwm-Sonoma
//
//  Created by qcwap on 2023/6/27.
//  Copyright © 2023 钟先耀. All rights reserved.
//
#include "AirportItlwmV2.hpp"
#include "AirportItlwmSkywalkInterface.hpp"
#include <sys/CTimeout.hpp>
#include <libkern/c++/OSMetaClass.h>
#include <crypto/sha1.h>
#include <net80211/ieee80211_node.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_priv.h>

/* REGFIX: request-side join counters (ioreg AIRPLAYJOIN*). */
static volatile UInt32 gJoinReq = 0;
static volatile UInt32 gJoinReqSAE = 0;
static volatile UInt32 gJoinReqPSK = 0;
static volatile UInt32 gJoinHandshakeReassocSkipped = 0;
static volatile UInt32 gJoinDisassocMidJoinIgnored = 0;
static volatile UInt32 gJoinDisassocDuplicateIgnored = 0; /* DISASSOCFIX */
static volatile UInt32 gJoinDisassocDuringJoin = 0;      /* DISASSOCFIX */
#ifndef LINK_STATE_DOWN
#define LINK_STATE_DOWN 2   /* sys/_if_ether.h */
#endif
/* SEQFIX state + counters (gSeq* without static are shared with AirportItlwmV2.cpp) */
volatile UInt32 gSeqVoluntaryDown = 0;   /* next link-down is one macOS asked for */
volatile UInt32 gSeqJoinInFlight = 0;    /* join requested, link not up yet */
volatile UInt32 gSeqStaleLinkDown = 0;   /* bumped in AirportItlwmV2::setLinkStatus */
volatile uint64_t gSeqDisassocStampMs = 0; /* SEQFIX probes: airport_up_time() stamps */
volatile uint64_t gSeqAssocStampMs = 0;
static volatile UInt32 gSeqDisassocSyncDown = 0;
static volatile UInt32 gSeqAssocSyncDown = 0;
static volatile UInt32 gSeqAssocDuringTeardown = 0;
static volatile UInt32 gSeqDownVolReads = 0;
static volatile UInt32 gSeqDownInvolReads = 0;
static volatile UInt32 gSeqScanRejectInit = 0;
static volatile UInt32 gScanGuardRejectWrapping = 0; /* SCANGUARD */
static volatile UInt32 gScanHealReset = 0;     /* SCANHEAL-20261017 */
static volatile uint64_t gScanWrapSetMs = 0;   /* SCANHEAL-20261017: airport_up_time() ms when latch set */
static volatile UInt32 gJoinPtkOK = 0;
static volatile UInt32 gJoinPtkLenMismatch = 0;
static volatile UInt32 gJoinPtkSetFail = 0;
static volatile UInt32 gJoinGtkOK = 0;
static volatile UInt32 gJoinGtkLenMismatch = 0;
static volatile UInt32 gJoinGtkSetFail = 0;

/*
 * Bitmask of the 00-0F-AC AKM suite types in an RSN IE:
 * bit 2 = PSK, bit 6 = PSK-SHA256, bit 8 = SAE, bit 4 = FT-PSK, bit 9 = FT-SAE.
 */
static UInt32 regfixRsnAkmMask(const u_int8_t *ie, size_t cap)
{
    if (ie == NULL || cap < 2 || ie[0] != 0x30)
        return 0;
    size_t len = (size_t)ie[1] + 2;
    if (len > cap)
        len = cap;
    size_t off = 2 + 2 + 4;                 /* id,len  version  group cipher */
    if (off + 2 > len)
        return 0;
    size_t pc = (size_t)ie[off] | ((size_t)ie[off + 1] << 8);
    off += 2 + 4 * pc;
    if (off + 2 > len)
        return 0;
    size_t ac = (size_t)ie[off] | ((size_t)ie[off + 1] << 8);
    off += 2;
    UInt32 mask = 0;
    for (size_t i = 0; i < ac && off + 4 <= len; i++, off += 4) {
        if (ie[off] == 0x00 && ie[off + 1] == 0x0F && ie[off + 2] == 0xAC &&
            ie[off + 3] < 32)
            mask |= (UInt32)1 << ie[off + 3];
    }
    return mask;
}


#define super IO80211InfraProtocol
OSDefineMetaClassAndStructors(AirportItlwmSkywalkInterface, IO80211InfraProtocol);

const char* hexdump(uint8_t *buf, size_t len) {
    ssize_t str_len = len * 3 + 1;
    char *str = (char*)IOMalloc(str_len);
    if (!str)
        return nullptr;
    for (size_t i = 0; i < len; i++)
    snprintf(str + 3 * i, (len - i) * 3, "%02x ", buf[i]);
    str[MAX(str_len - 2, 0)] = 0;
    return str;
}

static int ieeeChanFlag2appleScanFlagVentura(int flags)
{
    int ret = 0;
    if (flags & IEEE80211_CHAN_2GHZ)
        ret |= APPLE80211_C_FLAG_2GHZ;
    if (flags & IEEE80211_CHAN_5GHZ)
        ret |= APPLE80211_C_FLAG_5GHZ;
    ret |= (APPLE80211_C_FLAG_ACTIVE | APPLE80211_C_FLAG_20MHZ);
    return ret;
}

static int ieeeChanFlag2apple(int flags, int bw)
{
    int ret = 0;
    if (flags & IEEE80211_CHAN_2GHZ)
        ret |= APPLE80211_C_FLAG_2GHZ;
    if (flags & IEEE80211_CHAN_5GHZ)
        ret |= APPLE80211_C_FLAG_5GHZ;
    if (!(flags & IEEE80211_CHAN_PASSIVE))
        ret |= APPLE80211_C_FLAG_ACTIVE;
    if (flags & IEEE80211_CHAN_DFS)
        ret |= APPLE80211_C_FLAG_DFS;
    if (bw == -1) {
        if (flags & IEEE80211_CHAN_VHT) {
            if ((flags & IEEE80211_CHAN_VHT160) || (flags & IEEE80211_CHAN_VHT80_80))
                ret |= APPLE80211_C_FLAG_160MHZ;
            if (flags & IEEE80211_CHAN_VHT80)
                ret |= APPLE80211_C_FLAG_80MHZ;
        } else if ((flags & IEEE80211_CHAN_HT40) && (flags & IEEE80211_CHAN_HT)) {
            ret |= APPLE80211_C_FLAG_40MHZ;
            if (flags & IEEE80211_CHAN_HT40U)
                ret |= APPLE80211_C_FLAG_EXT_ABV;
        } else if (flags & IEEE80211_CHAN_HT20)
            ret |= APPLE80211_C_FLAG_20MHZ;
        else if ((flags & IEEE80211_CHAN_CCK) || (flags & IEEE80211_CHAN_OFDM))
            ret |= APPLE80211_C_FLAG_10MHZ;
    } else {
        switch (bw) {
            case IEEE80211_CHAN_WIDTH_80P80:
            case IEEE80211_CHAN_WIDTH_160:
                ret |= APPLE80211_C_FLAG_160MHZ;
                break;
            case IEEE80211_CHAN_WIDTH_80:
                ret |= APPLE80211_C_FLAG_80MHZ;
                break;
            case IEEE80211_CHAN_WIDTH_40:
                ret |= APPLE80211_C_FLAG_40MHZ;
                if (flags & IEEE80211_CHAN_HT40U)
                    ret |= APPLE80211_C_FLAG_EXT_ABV;
                break;
            case IEEE80211_CHAN_WIDTH_20:
                ret |= APPLE80211_C_FLAG_20MHZ;
                break;
            default:
                if (flags & IEEE80211_CHAN_HT20)
                    ret |= APPLE80211_C_FLAG_20MHZ;
                else if ((flags & IEEE80211_CHAN_CCK) || (flags & IEEE80211_CHAN_OFDM))
                    ret |= APPLE80211_C_FLAG_10MHZ;
                break;
        }
    }
    return ret;
}

const char *
AirportItlwmSkywalkInterface::getBSDNamePrefix(void)
{
    /*
     * Native Sonoma/Broadcom publishes the role-2 companion
     * as the LowLatency interface "llw0".
     *
     * Preserve normal behavior for Infrastructure role 1.
     */
    if (getInterfaceRole() == 2)
        return "llw";

    return super::getBSDNamePrefix();
}


void *AirportItlwmSkywalkInterface::createPeerManager(void)
{
    XYLog("AIRPLAY SKY: createPeerManager ENTER\n");

    void *result = super::createPeerManager();

    XYLog("AIRPLAY SKY: createPeerManager EXIT result=%p\n", result);

    return result;
}

IOReturn AirportItlwmSkywalkInterface::reportDataPathEvents(UInt a, void *b, unsigned long c, bool d)
{
    IOLog("AIRPLAY SKY TRACE: reportDataPathEvents a=%u b=%p c=%lu d=%d\n",
          a, b, c, d);

    IOReturn result = super::reportDataPathEvents(a, b, c, d);

    IOLog("AIRPLAY SKY TRACE: reportDataPathEvents RETURN=%d\n", result);
    return result;
}

void AirportItlwmSkywalkInterface::setDataPathState(bool state)
{
    IOLog("AIRPLAY SKY TRACE: setDataPathState state=%d\n", state);
    super::setDataPathState(state);
}

void *AirportItlwmSkywalkInterface::getP2PSkywalkPeerMgr(void)
{
    IOLog("AIRPLAY SKY TRACE: getP2PSkywalkPeerMgr ENTER\n");

    void *result = super::getP2PSkywalkPeerMgr();

    IOLog("AIRPLAY SKY TRACE: getP2PSkywalkPeerMgr RETURN=%p\n", result);
    return result;
}

void AirportItlwmSkywalkInterface::associateSSID(uint8_t *ssid, uint32_t ssid_len, const struct ether_addr &bssid, uint32_t authtype_lower, uint32_t authtype_upper, uint8_t *key, uint32_t key_len, int key_index)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    ic->ic_flags &= ~IEEE80211_F_AUTO_JOIN;
    
    ieee80211_disable_rsn(ic);
    ieee80211_disable_wep(ic);
    
    struct ieee80211_wpaparams     wpa;
    struct ieee80211_nwkey         nwkey;
    bzero(&wpa, sizeof(wpa));
    bzero(&nwkey, sizeof(nwkey));
    
    memset(ic->ic_des_essid, 0, IEEE80211_NWID_LEN);
    memcpy(ic->ic_des_essid, ssid, ssid_len);
    ic->ic_des_esslen = ssid_len;
    
    bool is_zero = true;
    for (int i = 0; i < IEEE80211_ADDR_LEN; i++)
    is_zero &= bssid.octet[i] == 0;
    
    if (!is_zero) {
        IEEE80211_ADDR_COPY(ic->ic_des_bssid, bssid.octet);
        ic->ic_flags |= IEEE80211_F_DESBSSID;
    }
    else {
        memset(ic->ic_des_bssid, 0, IEEE80211_ADDR_LEN);
        ic->ic_flags &= ~IEEE80211_F_DESBSSID;
    }

    // AUTHTYPE_WPA3_SAE AUTHTYPE_WPA3_FT_SAE
    // we don't really support WPA3, but we have announced we support WPA3 in card capability function. so we fake it as WPA2 to support some WPA2/WPA3 mix wifi connection.
    if (authtype_upper == APPLE80211_AUTHTYPE_WPA3_SAE || authtype_upper == APPLE80211_AUTHTYPE_WPA3_FT_SAE) {
        wpa.i_protos |= IEEE80211_WPA_PROTO_WPA2;
        authtype_upper |= APPLE80211_AUTHTYPE_WPA2_PSK;// hack
    }
    // AUTHTYPE_WPA3_ENTERPRISE AUTHTYPE_WPA3_FT_ENTERPRISE
    if (authtype_upper == APPLE80211_AUTHTYPE_WPA3_ENTERPRISE || authtype_upper == APPLE80211_AUTHTYPE_WPA3_FT_ENTERPRISE) {
        wpa.i_protos |= IEEE80211_WPA_PROTO_WPA2;
        authtype_upper |= APPLE80211_AUTHTYPE_WPA2;// hack
    }
    
    if (authtype_upper & (APPLE80211_AUTHTYPE_WPA | APPLE80211_AUTHTYPE_WPA_PSK | APPLE80211_AUTHTYPE_WPA2 | APPLE80211_AUTHTYPE_WPA2_PSK | APPLE80211_AUTHTYPE_SHA256_PSK | APPLE80211_AUTHTYPE_SHA256_8021X)) {
        XYLog("%s %d\n", __FUNCTION__, __LINE__);
        wpa.i_protos = IEEE80211_WPA_PROTO_WPA1 | IEEE80211_WPA_PROTO_WPA2;
    }
    
    if (authtype_upper & (APPLE80211_AUTHTYPE_WPA_PSK | APPLE80211_AUTHTYPE_WPA2_PSK | APPLE80211_AUTHTYPE_SHA256_PSK)) {
        XYLog("%s %d\n", __FUNCTION__, __LINE__);
        wpa.i_akms |= IEEE80211_WPA_AKM_PSK | IEEE80211_WPA_AKM_SHA256_PSK;
        wpa.i_enabled = 1;
        memcpy(ic->ic_psk, key, sizeof(ic->ic_psk));
        ic->ic_flags |= IEEE80211_F_PSK;
        ieee80211_ioctl_setwpaparms(ic, &wpa);
    }
    if (authtype_upper & (APPLE80211_AUTHTYPE_WPA | APPLE80211_AUTHTYPE_WPA2 | APPLE80211_AUTHTYPE_SHA256_8021X)) {
        XYLog("%s %d\n", __FUNCTION__, __LINE__);
        wpa.i_akms |= IEEE80211_WPA_AKM_8021X | IEEE80211_WPA_AKM_SHA256_8021X;
        wpa.i_enabled = 1;
        ieee80211_ioctl_setwpaparms(ic, &wpa);
    }
    
    if (authtype_lower == APPLE80211_AUTHTYPE_SHARED) {
        XYLog("shared key authentication is not supported!\n");
        return;
    }
    
    if (authtype_upper == APPLE80211_AUTHTYPE_NONE && authtype_lower == APPLE80211_AUTHTYPE_OPEN) { // Open or WEP Open System
        if (key_len > 0) {
            XYLog("%s %d\n", __FUNCTION__, __LINE__);
            nwkey.i_wepon = IEEE80211_NWKEY_WEP;
            nwkey.i_defkid = key_index + 1;
            nwkey.i_key[key_index].i_keylen = (int)key_len;
            nwkey.i_key[key_index].i_keydat = key;
            ieee80211_ioctl_setnwkeys(ic, &nwkey);
        }
    }
}

void AirportItlwmSkywalkInterface::setPTK(const u_int8_t *key, size_t key_len) {
    struct ieee80211com *ic = fHalService->get80211Controller();
    struct ieee80211_node    * ni = ic->ic_bss;
    struct ieee80211_key *k;
    int keylen;
    
    ni->ni_rsn_supp_state = RNSA_SUPP_PTKDONE;
    
    if (ni->ni_rsncipher != IEEE80211_CIPHER_USEGROUP) {
        u_int64_t prsc;
        
        /* check that key length matches that of pairwise cipher */
        keylen = ieee80211_cipher_keylen(ni->ni_rsncipher);
        if (key_len != keylen) {
            XYLog("PTK length mismatch. expected %d, got %zu\n", keylen, key_len);
            instance->setProperty("AIRPLAYJOINPtkLenMismatch",
                (unsigned long long)__sync_add_and_fetch(&gJoinPtkLenMismatch, (UInt32)1), 32);
            return;
        }
        prsc = /*(gtk == NULL) ? LE_READ_6(key->rsc) :*/ 0;
        
        /* map PTK to 802.11 key */
        k = &ni->ni_pairwise_key;
        memset(k, 0, sizeof(*k));
        k->k_cipher = ni->ni_rsncipher;
        k->k_rsc[0] = prsc;
        k->k_len = keylen;
        memcpy(k->k_key, key, k->k_len);
        /* install the PTK */
        if ((*ic->ic_set_key)(ic, ni, k) != 0) {
            XYLog("setting PTK failed\n");
            instance->setProperty("AIRPLAYJOINPtkSetFail",
                (unsigned long long)__sync_add_and_fetch(&gJoinPtkSetFail, (UInt32)1), 32);
            return;
        }
        else {
            XYLog("setting PTK successfully\n");
            instance->setProperty("AIRPLAYJOINPtkOK",
                (unsigned long long)__sync_add_and_fetch(&gJoinPtkOK, (UInt32)1), 32);
        }
        ni->ni_flags &= ~IEEE80211_NODE_RSN_NEW_PTK;
        ni->ni_flags &= ~IEEE80211_NODE_TXRXPROT;
        ni->ni_flags |= IEEE80211_NODE_RXPROT;
    } else if (ni->ni_rsncipher != IEEE80211_CIPHER_USEGROUP)
        XYLog("%s: unexpected pairwise key update received from %s\n",
              ic->ic_if.if_xname, ether_sprintf(ni->ni_macaddr));
}

void AirportItlwmSkywalkInterface::setGTK(const u_int8_t *gtk, size_t key_len, u_int8_t kid, u_int8_t *rsc) {
    struct ieee80211com *ic = fHalService->get80211Controller();
    struct ieee80211_node    * ni = ic->ic_bss;
    struct ieee80211_key *k;
    int keylen;
    
    if (gtk != NULL) {
        /* check that key length matches that of group cipher */
        keylen = ieee80211_cipher_keylen(ni->ni_rsngroupcipher);
        if (key_len != keylen) {
            XYLog("GTK length mismatch. expected %d, got %zu\n", keylen, key_len);
            instance->setProperty("AIRPLAYJOINGtkLenMismatch",
                (unsigned long long)__sync_add_and_fetch(&gJoinGtkLenMismatch, (UInt32)1), 32);
            return;
        }
        /* map GTK to 802.11 key */
        k = &ic->ic_nw_keys[kid];
        if (k->k_cipher == IEEE80211_CIPHER_NONE || k->k_len != keylen || memcmp(k->k_key, gtk, keylen) != 0) {
            memset(k, 0, sizeof(*k));
            k->k_id = kid;    /* 0-3 */
            k->k_cipher = ni->ni_rsngroupcipher;
            k->k_flags = IEEE80211_KEY_GROUP;
            //if (gtk[6] & (1 << 2))
            //  k->k_flags |= IEEE80211_KEY_TX;
            k->k_rsc[0] = LE_READ_6(rsc);
            k->k_len = keylen;
            memcpy(k->k_key, gtk, k->k_len);
            /* install the GTK */
            if ((*ic->ic_set_key)(ic, ni, k) != 0) {
                XYLog("setting GTK failed\n");
                instance->setProperty("AIRPLAYJOINGtkSetFail",
                    (unsigned long long)__sync_add_and_fetch(&gJoinGtkSetFail, (UInt32)1), 32);
                return;
            }
            else {
                XYLog("setting GTK successfully\n");
                instance->setProperty("AIRPLAYJOINGtkOK",
                    (unsigned long long)__sync_add_and_fetch(&gJoinGtkOK, (UInt32)1), 32);
            }
        }
    }
    
    if (true) {
        ni->ni_flags |= IEEE80211_NODE_TXRXPROT;
#ifndef IEEE80211_STA_ONLY
        if (ic->ic_opmode != IEEE80211_M_IBSS ||
            ++ni->ni_key_count == 2)
#endif
        {
            XYLog("marking port %s valid\n",
                  ether_sprintf(ni->ni_macaddr));
            ni->ni_port_valid = 1;
            ieee80211_set_link_state(ic, LINK_STATE_UP);
            ni->ni_assoc_fail = 0;
            if (ic->ic_opmode == IEEE80211_M_STA)
                ic->ic_rsngroupcipher = ni->ni_rsngroupcipher;
        }
    }
}


IOReturn AirportItlwmSkywalkInterface::
setVIRTUAL_IF_CREATE(apple80211_virt_if_create_data *)
{
    /*
     * Match the KGP reference behavior.
     * The Skywalk interface does not consume VIRTUAL_IF_CREATE.
     */
    return kIOReturnUnsupported;
}


bool AirportItlwmSkywalkInterface::
init(IOService *provider)
{
    bool ret = IO80211InfraInterface::init();
    if (!ret) {
        XYLog("%s IO80211InfraInterface init failed\n", __PRETTY_FUNCTION__);
        return false;
    }
    instance = OSDynamicCast(AirportItlwm, provider);
    if (!instance)
        return false;
    this->fHalService = instance->fHalService;
    this->scanSource = instance->scanSource;

    instance->setProperty(
        "AJB26ProbeVersion",
        (unsigned long long)2602, 32);

    instance->setProperty(
        "AJB26SkyInit",
        (unsigned long long)1, 8);

    return ret;
}

//ifnet_t AirportItlwmSkywalkInterface::
//getBSDInterface()
//{
//    if (instance->bsdInterface)
//        return instance->bsdInterface->getIfnet();
//    return NULL;
//}

IOReturn AirportItlwmSkywalkInterface::
getSSID(struct apple80211_ssid_data *sd)
{
    struct ieee80211com * ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(sd, 0, sizeof(*sd));
        sd->version = APPLE80211_VERSION;
        memcpy(sd->ssid_bytes, ic->ic_des_essid, strlen((const char*)ic->ic_des_essid));
        sd->ssid_len = (uint32_t)strlen((const char*)ic->ic_des_essid);
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getAUTH_TYPE(struct apple80211_authtype_data *ad)
{
    ad->version = APPLE80211_VERSION;
    ad->authtype_lower = current_authtype_lower;
    ad->authtype_upper = current_authtype_upper;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setAUTH_TYPE(struct apple80211_authtype_data *ad)
{
    current_authtype_lower = ad->authtype_lower;
    current_authtype_upper = ad->authtype_upper;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setCIPHER_KEY(struct apple80211_key *key)
{
    XYLog("%s\n", __FUNCTION__);
    const char* keydump = hexdump(key->key, key->key_len);
    const char* rscdump = hexdump(key->key_rsc, key->key_rsc_len);
    const char* eadump = hexdump(key->key_ea.octet, APPLE80211_ADDR_LEN);
    static_assert(__offsetof(struct apple80211_key, key_ea) == 92, "struct corrupted");
    static_assert(__offsetof(struct apple80211_key, key_rsc_len) == 80, "struct corrupted");
    static_assert(__offsetof(struct apple80211_key, wowl_kck_len) == 100, "struct corrupted");
    static_assert(__offsetof(struct apple80211_key, wowl_kek_len) == 120, "struct corrupted");
    static_assert(__offsetof(struct apple80211_key, wowl_kck_key) == 104, "struct corrupted");
    if (keydump && rscdump && eadump)
        XYLog("Set key request: len=%d cipher_type=%d flags=%d index=%d key=%s rsc_len=%d rsc=%s ea=%s\n",
              key->key_len, key->key_cipher_type, key->key_flags, key->key_index, keydump, key->key_rsc_len, rscdump, eadump);
    else
        XYLog("Set key request, but failed to allocate memory for hexdump\n");
    
    if (keydump)
        IOFree((void*)keydump, 3 * key->key_len + 1);
    if (rscdump)
        IOFree((void*)rscdump, 3 * key->key_rsc_len + 1);
    if (eadump)
        IOFree((void*)eadump, 3 * APPLE80211_ADDR_LEN + 1);
    
    switch (key->key_cipher_type) {
        case APPLE80211_CIPHER_NONE:
            // clear existing key
//            XYLog("Setting NONE key is not supported\n");
            break;
        case APPLE80211_CIPHER_WEP_40:
        case APPLE80211_CIPHER_WEP_104:
            XYLog("Setting WEP key %d is not supported\n", key->key_index);
            break;
        case APPLE80211_CIPHER_TKIP:
        case APPLE80211_CIPHER_AES_OCB:
        case APPLE80211_CIPHER_AES_CCM:
            switch (key->key_flags) {
                case 4: // PTK
                    setPTK(key->key, key->key_len);
                    break;
                case 0: // GTK
                    setGTK(key->key, key->key_len, key->key_index, key->key_rsc);
                    break;
            }
            break;
        case APPLE80211_CIPHER_PMK:
            XYLog("Setting WPA PMK is not supported\n");
            break;
        case APPLE80211_CIPHER_MSK:
            XYLog("Setting MSK\n");
            ieee80211_pmksa_add(fHalService->get80211Controller(), IEEE80211_AKM_8021X,
                                fHalService->get80211Controller()->ic_bss->ni_macaddr, key->key, 0);
            break;
        case APPLE80211_CIPHER_PMKSA:
            XYLog("Setting WPA PMKSA\n");
            ieee80211_pmksa_add(fHalService->get80211Controller(), IEEE80211_AKM_8021X,
                                fHalService->get80211Controller()->ic_bss->ni_macaddr, key->key, 0);
            break;
    }
    //fInterface->postMessage(APPLE80211_M_CIPHER_KEY_CHANGED);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getPHY_MODE(struct apple80211_phymode_data *pd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    
    pd->version = APPLE80211_VERSION;
    pd->phy_mode = APPLE80211_MODE_11A
    | APPLE80211_MODE_11B
    | APPLE80211_MODE_11G
    | APPLE80211_MODE_11N;
    
    if (ic->ic_flags & IEEE80211_F_VHTON)
        pd->phy_mode |= APPLE80211_MODE_11AC;
    
    if (ic->ic_flags & IEEE80211_F_HEON)
        pd->phy_mode |= APPLE80211_MODE_11AX;
    
    switch (fHalService->get80211Controller()->ic_curmode) {
        case IEEE80211_MODE_AUTO:
            pd->active_phy_mode = APPLE80211_MODE_AUTO;
            break;
        case IEEE80211_MODE_11A:
            pd->active_phy_mode = APPLE80211_MODE_11A;
            break;
        case IEEE80211_MODE_11B:
            pd->active_phy_mode = APPLE80211_MODE_11B;
            break;
        case IEEE80211_MODE_11G:
            pd->active_phy_mode = APPLE80211_MODE_11G;
            break;
        case IEEE80211_MODE_11N:
            pd->active_phy_mode = APPLE80211_MODE_11N;
            break;
        case IEEE80211_MODE_11AC:
            pd->active_phy_mode = APPLE80211_MODE_11AC;
            break;
        case IEEE80211_MODE_11AX:
            pd->active_phy_mode = APPLE80211_MODE_11AX;
            break;
            
        default:
            pd->active_phy_mode = APPLE80211_MODE_AUTO;
            break;
    }
    
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getCHANNEL(struct apple80211_channel_data *cd)
{
    struct ieee80211com * ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(cd, 0, sizeof(apple80211_channel_data));
        cd->version = APPLE80211_VERSION;
        cd->channel.version = APPLE80211_VERSION;
        cd->channel.channel = ieee80211_chan2ieee(ic, ic->ic_bss->ni_chan);
        cd->channel.flags = ieeeChanFlag2apple(ic->ic_bss->ni_chan->ic_flags, ic->ic_bss->ni_chw);
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getSTATE(struct apple80211_state_data *sd)
{
    memset(sd, 0, sizeof(*sd));
    sd->version = APPLE80211_VERSION;
    sd->state = fHalService->get80211Controller()->ic_state;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getMCS_INDEX_SET(struct apple80211_mcs_index_set_data *ad)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(ad, 0, sizeof(*ad));
        ad->version = APPLE80211_VERSION;
        size_t size = min(ARRAY_SIZE(ic->ic_bss->ni_rxmcs), ARRAY_SIZE(ad->mcs_set_map));
        for (int i = 0; i < size; i++)
            ad->mcs_set_map[i] = ic->ic_bss->ni_rxmcs[i];
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getVHT_MCS_INDEX_SET(struct apple80211_vht_mcs_index_set_data *data)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_bss == NULL || ic->ic_curmode < IEEE80211_MODE_11AC) {
        return kIOReturnError;
    }
    memset(data, 0, sizeof(struct apple80211_vht_mcs_index_set_data));
    data->version = APPLE80211_VERSION;
    data->mcs_map = ic->ic_bss->ni_vht_mcsinfo.tx_mcs_map;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getMCS_VHT(struct apple80211_mcs_vht_data *data)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_bss == NULL || ic->ic_curmode < IEEE80211_MODE_11AC) {
        return kIOReturnError;
    }
    memset(data, 0, sizeof(struct apple80211_mcs_vht_data));
    data->version = APPLE80211_VERSION;
    data->guard_interval = (ieee80211_node_supports_vht_sgi80(ic->ic_bss) || ieee80211_node_supports_vht_sgi160(ic->ic_bss)) ? APPLE80211_GI_SHORT : APPLE80211_GI_LONG;
    data->index = ic->ic_bss->ni_txmcs;
    data->nss = fHalService->getDriverInfo()->getTxNSS();
    switch (ic->ic_bss->ni_chw) {
        case IEEE80211_CHAN_WIDTH_40:
            data->bw = 40;
            break;
        case IEEE80211_CHAN_WIDTH_80:
            data->bw = 80;
            break;
        case IEEE80211_CHAN_WIDTH_80P80:
        case IEEE80211_CHAN_WIDTH_160:
            data->bw = 160;
            break;
            
        default:
            data->bw = 20;
            break;
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getRATE_SET(struct apple80211_rate_set_data *ad)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(ad, 0, sizeof(*ad));
        ad->version = APPLE80211_VERSION;
        ad->num_rates = ic->ic_bss->ni_rates.rs_nrates;
        size_t size = min(ic->ic_bss->ni_rates.rs_nrates, ARRAY_SIZE(ad->rates));
        for (int i=0; i < size; i++) {
            struct apple80211_rate apple_rate = ad->rates[i];
            apple_rate.version = APPLE80211_VERSION;
            apple_rate.rate = ic->ic_bss->ni_rates.rs_rates[i];
            apple_rate.flags = 0;
        }
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getOP_MODE(struct apple80211_opmode_data *od)
{
    od->version = APPLE80211_VERSION;
    od->op_mode = APPLE80211_M_STA;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getTXPOWER(struct apple80211_txpower_data *txd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(txd, 0, sizeof(*txd));
        txd->version = APPLE80211_VERSION;
        txd->txpower = ic->ic_txpower;
        txd->txpower_unit = APPLE80211_UNIT_PERCENT;
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getRATE(struct apple80211_rate_data *rd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_bss == NULL)
        return 6;
    int nss;
    int sgi;
    int index = 0;
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(rd, 0, sizeof(*rd));
        rd->version = APPLE80211_VERSION;
        rd->num_radios = 1;
        sgi = ieee80211_node_supports_sgi(ic->ic_bss);
        if (ic->ic_curmode == IEEE80211_MODE_11AC) {
            if (sgi)
                index += 1;
            nss = fHalService->getDriverInfo()->getTxNSS();
            switch (ic->ic_bss->ni_chw) {
                case IEEE80211_CHAN_WIDTH_40:
                    index += 4;
                    break;
                case IEEE80211_CHAN_WIDTH_80:
                    index += 8;
                    break;
                case IEEE80211_CHAN_WIDTH_80P80:
                case IEEE80211_CHAN_WIDTH_160:
                    index += 12;
                    break;

                default:
                    break;
            }
            index += 2 * (nss - 1);
            const struct ieee80211_vht_rateset *rs = &ieee80211_std_ratesets_11ac[index];
            rd->rate[0] = rs->rates[ic->ic_bss->ni_txmcs % rs->nrates] / 2;
        } else if (ic->ic_curmode == IEEE80211_MODE_11N) {
            int is_40mhz = ic->ic_bss->ni_chw == IEEE80211_CHAN_WIDTH_40;
            if (sgi)
                index += 1;
            if (is_40mhz)
                index += (IEEE80211_HT_RATESET_MIMO4_SGI + 1);
            index += (ic->ic_bss->ni_txmcs / 16);
            nss = ic->ic_bss->ni_txmcs / 8 + 1;
            index += 2 * (nss - 1);
            rd->rate[0] = ieee80211_std_ratesets_11n[index].rates[ic->ic_bss->ni_txmcs % 8] / 2;
        } else
            rd->rate[0] = ic->ic_bss->ni_rates.rs_rates[ic->ic_bss->ni_txrate];
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getBSSID(struct apple80211_bssid_data *bd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(bd, 0, sizeof(*bd));
        bd->version = APPLE80211_VERSION;
        memcpy(bd->bssid.octet, ic->ic_bss->ni_bssid, APPLE80211_ADDR_LEN);
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getRSSI(struct apple80211_rssi_data *rd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(rd, 0, sizeof(*rd));
        rd->num_radios = 1;
        rd->rssi_unit = APPLE80211_UNIT_DBM;
        rd->rssi[0] = rd->aggregate_rssi
        = rd->rssi_ext[0]
        = rd->aggregate_rssi_ext
        = -(0 - IWM_MIN_DBM - ic->ic_bss->ni_rssi);
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getRSN_IE(struct apple80211_rsn_ie_data *data)
{
#ifdef USE_APPLE_SUPPLICANT
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_bss == NULL || ic->ic_bss->ni_rsnie == NULL) {
        return kIOReturnError;
    }
    data->version = APPLE80211_VERSION;
    if (ic->ic_rsn_ie_override[1] > 0) {
        data->len = 2 + ic->ic_rsn_ie_override[1];
        memcpy(data->ie, ic->ic_rsn_ie_override, data->len);
    }
    else {
        data->len = 2 + ic->ic_bss->ni_rsnie[1];
        memcpy(data->ie, ic->ic_bss->ni_rsnie, data->len);
    }
    return kIOReturnSuccess;
#else
    return kIOReturnUnsupported;
#endif
}

IOReturn AirportItlwmSkywalkInterface::
setRSN_IE(struct apple80211_rsn_ie_data *data)
{
#ifdef USE_APPLE_SUPPLICANT
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (!data)
        return kIOReturnError;
    static_assert(sizeof(ic->ic_rsn_ie_override) == APPLE80211_MAX_RSN_IE_LEN, "Max RSN IE length mismatch");
    memcpy(ic->ic_rsn_ie_override, data->ie, APPLE80211_MAX_RSN_IE_LEN);
    if (ic->ic_state == IEEE80211_S_RUN && ic->ic_bss != nullptr)
        ieee80211_save_ie(data->ie, &ic->ic_bss->ni_rsnie);
    return kIOReturnSuccess;
#else
    return kIOReturnUnsupported;
#endif
}

IOReturn AirportItlwmSkywalkInterface::
getAP_IE_LIST(struct apple80211_ap_ie_data *data)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (!data)
        return kIOReturnError;
    if (ic->ic_bss == NULL || ic->ic_bss->ni_rsnie_tlv == NULL || ic->ic_bss->ni_rsnie_tlv_len == 0 || ic->ic_bss->ni_rsnie_tlv_len > data->len || ic->ic_bss->ni_rsnie_tlv_len > 1024)
        return kIOReturnError;
    data->version = APPLE80211_VERSION;
    data->len = ic->ic_bss->ni_rsnie_tlv_len;
    memcpy(data->ie_data, ic->ic_bss->ni_rsnie_tlv, data->len);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getNOISE(struct apple80211_noise_data *nd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(nd, 0, sizeof(*nd));
        nd->version = APPLE80211_VERSION;
        nd->num_radios = 1;
        nd->noise[0]
        = nd->aggregate_noise = fHalService->getDriverInfo()->getBSSNoise(); /* NOISEFIX: already dBm (negative), no sign flip */
        nd->noise_unit = APPLE80211_UNIT_DBM;
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getPOWERSAVE(struct apple80211_powersave_data *pd)
{
    pd->version = APPLE80211_VERSION;
    pd->powersave_level = APPLE80211_POWERSAVE_MODE_DISABLED;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getNSS(struct apple80211_nss_data *data)
{
    memset(data, 0, sizeof(*data));
    data->version = APPLE80211_VERSION;
    data->nss = fHalService->getDriverInfo()->getTxNSS();
    return kIOReturnSuccess;
}

static volatile UInt32 gAJB26SkyAssocEnter = 0;
static volatile UInt32 gAJB26SkyAssocSkipPreScan = 0;
static volatile UInt32 gAJB26SkyAssocSkipAuthAssoc = 0;
static volatile UInt32 gAJB26SkyDisassocEnter = 0;
static volatile UInt32 gAJB26SkyDisassocSkipPreScan = 0;
static volatile UInt32 gAJB26SkyDisassocSkipAuthAssoc = 0;

/* JOINFAST-20261010: shared with ItlIwx.cpp (see setASSOCIATE) */
extern volatile UInt32 gJoinFastAbortReq;
static volatile UInt32 gJoinFastReq = 0;
static volatile UInt32 gJoinFastNodeFound = 0;
static volatile UInt32 gJoinFastNoNode = 0;
static volatile UInt32 gJoinFastAbortQueued = 0;
static volatile UInt32 gJoinFastNotScanState = 0;

IOReturn AirportItlwmSkywalkInterface::
setASSOCIATE(struct apple80211_assoc_data *ad)
{
    if (!ad)
        return kIOReturnError;
    
    XYLog("%s mode=%d ad_ssid_len=%u ad_auth_lower=%d ad_auth_upper=%d rsn_ie_len=%u\n",
          __FUNCTION__, ad->ad_mode, (unsigned int)ad->ad_ssid_len,
          ad->ad_auth_lower, ad->ad_auth_upper, (unsigned int)ad->ad_rsn_ie_len);
    
    struct apple80211_rsn_ie_data rsn_ie_data;
    struct apple80211_authtype_data auth_type_data;
    struct ieee80211com *ic = fHalService->get80211Controller();
    enum ieee80211_state state = ic->ic_state;

    UInt32 ajb26Enter = __sync_add_and_fetch(
        &gAJB26SkyAssocEnter, (UInt32)1);
    instance->setProperty(
        "AJB26SkyAssocEnter",
        (unsigned long long)ajb26Enter, 32);
    instance->setProperty(
        "AJB26SkyAssocLastState",
        (unsigned long long)(UInt32)state, 32);

    {
        UInt32 n = __sync_add_and_fetch(&gJoinReq, (UInt32)1);
        instance->setProperty("AIRPLAYJOINReqCount", (unsigned long long)n, 32);
        instance->setProperty("AIRPLAYJOINReqLastState",
                              (unsigned long long)(UInt32)state, 32);
        instance->setProperty("AIRPLAYJOINReqLastAuthUpper",
                              (unsigned long long)(UInt32)ad->ad_auth_upper, 32);
        instance->setProperty("AIRPLAYJOINReqLastAuthLower",
                              (unsigned long long)(UInt32)ad->ad_auth_lower, 32);
        instance->setProperty("AIRPLAYJOINReqLastKeyLen",
                              (unsigned long long)(UInt32)ad->ad_key.key_len, 32);
        instance->setProperty("AIRPLAYJOINReqLastAkmMask",
                              (unsigned long long)regfixRsnAkmMask(ad->ad_rsn_ie, sizeof(ad->ad_rsn_ie)), 32);
        if (ad->ad_auth_upper & (APPLE80211_AUTHTYPE_WPA3_SAE | APPLE80211_AUTHTYPE_WPA3_FT_SAE)) {
            UInt32 s = __sync_add_and_fetch(&gJoinReqSAE, (UInt32)1);
            instance->setProperty("AIRPLAYJOINReqSAE", (unsigned long long)s, 32);
        }
        if (ad->ad_auth_upper & (APPLE80211_AUTHTYPE_WPA_PSK | APPLE80211_AUTHTYPE_WPA2_PSK | APPLE80211_AUTHTYPE_SHA256_PSK)) {
            UInt32 p = __sync_add_and_fetch(&gJoinReqPSK, (UInt32)1);
            instance->setProperty("AIRPLAYJOINReqPSK", (unsigned long long)p, 32);
        }
    }

    if (ad->ad_ssid_len > APPLE80211_MAX_SSID_LEN)
        return kIOReturnError;

    if (ad->ad_mode == APPLE80211_AP_MODE_IBSS)
        return kIOReturnSuccess;

    /*
     * SWITCHFIX: upstream silently returned success (and did NOTHING) when
     * ic_state was INIT, AUTH or ASSOC. airportd then waited out its 10s
     * assoc timeout before re-sending -- the "click it again" symptom.
     * Now: only skip when we are already mid-join to the SAME network.
     */
    bool sameDesired =
        (UInt32)ic->ic_des_esslen == ad->ad_ssid_len &&
        memcmp(ic->ic_des_essid, ad->ad_ssid, ad->ad_ssid_len) == 0;

    if ((state == IEEE80211_S_AUTH || state == IEEE80211_S_ASSOC) && sameDesired) {
        UInt32 ajb26Skip = __sync_add_and_fetch(
            &gAJB26SkyAssocSkipAuthAssoc, (UInt32)1);
        instance->setProperty(
            "AJB26SkyAssocSkipAuthAssoc",
            (unsigned long long)ajb26Skip, 32);
        return kIOReturnSuccess;
    }

    /*
     * REGFIX: a repeat ASSOCIATE for the network we are already on while the
     * 4-way handshake is still running. associateSSID() would disable RSN and
     * reload the PSK mid-handshake, breaking it (airportd then thinks the
     * password is wrong and prompts for it). Let the handshake finish.
     */
    if (state == IEEE80211_S_RUN && ic->ic_bss != NULL &&
        (ic->ic_flags & IEEE80211_F_RSNON) && !ic->ic_bss->ni_port_valid &&
        (UInt32)ic->ic_bss->ni_esslen == ad->ad_ssid_len &&
        memcmp(ic->ic_bss->ni_essid, ad->ad_ssid, ad->ad_ssid_len) == 0) {
        UInt32 h = __sync_add_and_fetch(&gJoinHandshakeReassocSkipped, (UInt32)1);
        instance->setProperty("AIRPLAYJOINHandshakeReassocSkipped",
                              (unsigned long long)h, 32);
        return kIOReturnSuccess;
    }

    /* Are we currently up on exactly the network being requested? */
    bool onRequested = false;
    if (state == IEEE80211_S_RUN && ic->ic_bss != NULL) {
        onRequested =
            (UInt32)ic->ic_bss->ni_esslen == ad->ad_ssid_len &&
            memcmp(ic->ic_bss->ni_essid, ad->ad_ssid, ad->ad_ssid_len) == 0;
    }

    /* Leaving the current/in-progress network: tell the AP before rekeying. */
    bool mustRescan = !onRequested &&
        (state == IEEE80211_S_RUN || state == IEEE80211_S_AUTH ||
         state == IEEE80211_S_ASSOC);
    if (mustRescan && state > IEEE80211_S_AUTH && ic->ic_bss != NULL)
        IEEE80211_SEND_MGMT(ic, ic->ic_bss, IEEE80211_FC0_SUBTYPE_DEAUTH,
                            IEEE80211_REASON_AUTH_LEAVE);

    /*
     * SEQFIX: race detector. macOS already asked to disconnect, but the old
     * link is still reported up when the new join arrives. Before SEQFIX this
     * was the normal case; with the fix it should stay 0.
     */
    if (gSeqVoluntaryDown && (instance->currentStatus & kIONetworkLinkActive)) {
        UInt32 r = __sync_add_and_fetch(&gSeqAssocDuringTeardown, (UInt32)1);
        instance->setProperty("AIRPLAYSEQAssocDuringTeardown", (unsigned long long)r, 32);
    }

    /*
     * SEQFIX: leaving a live link for another network without a DISASSOCIATE
     * first. Report the old link down NOW (voluntary), before the new join
     * starts, so airportd never sees it arrive mid-join.
     */
    if (mustRescan && (instance->currentStatus & kIONetworkLinkActive)) {
        __sync_lock_test_and_set(&gSeqVoluntaryDown, (UInt32)1);
        disassocIsVoluntary = true;
        ic->ic_deauth_reason = APPLE80211_REASON_ASSOC_LEAVING;
        ieee80211_set_link_state(ic, LINK_STATE_DOWN);
        UInt32 a = __sync_add_and_fetch(&gSeqAssocSyncDown, (UInt32)1);
        instance->setProperty("AIRPLAYSEQAssocSyncLinkDown", (unsigned long long)a, 32);
        XYLog("SEQFIX: switch from live link - link down reported before join\n");
    }
    __sync_lock_test_and_set(&gSeqJoinInFlight, (UInt32)1);
    instance->setProperty("AIRPLAYSEQJoinInFlight", (unsigned long long)1, 32);
    {
        uint64_t now = airport_up_time();
        if (gSeqDisassocStampMs != 0 && now >= gSeqDisassocStampMs &&
            now - gSeqDisassocStampMs < 60000) {
            instance->setProperty("AIRPLAYSEQDisassocToAssocMs",
                                  (unsigned long long)(now - gSeqDisassocStampMs), 32);
        }
        gSeqDisassocStampMs = 0;
        gSeqAssocStampMs = now;
    }

    /* Always record the requested target (ic_des_essid, RSN, keys). */
    disassocIsVoluntary = false;
    auth_type_data.version = APPLE80211_VERSION;
    auth_type_data.authtype_upper = ad->ad_auth_upper;
    auth_type_data.authtype_lower = ad->ad_auth_lower;
    setAUTH_TYPE(&auth_type_data);
    rsn_ie_data.version = APPLE80211_VERSION;
    rsn_ie_data.len = ad->ad_rsn_ie[1] + 2;
    memcpy(rsn_ie_data.ie, ad->ad_rsn_ie, rsn_ie_data.len);
    setRSN_IE(&rsn_ie_data);

    associateSSID(ad->ad_ssid, ad->ad_ssid_len, ad->ad_bssid, ad->ad_auth_lower, ad->ad_auth_upper, ad->ad_key.key, ad->ad_key.key_len, ad->ad_key.key_index);

    /*
     * JOINFAST-20261010: the BCM reference is connected ~0.2 s after macOS
     * hands it the join. We waited for the full all-channel firmware scan that
     * the preceding DISASSOCIATE started, and only end_scan picked the target:
     * SEQAssocToLinkUpMs 4.3-4.7 s on every switch. If the BSSID macOS asked
     * for is already in the scan table, end that scan now. The firmware's
     * scan-complete then runs the normal end_scan -> choose_bss -> join path.
     */
    {
        UInt32 jr = __sync_add_and_fetch(&gJoinFastReq, (UInt32)1);
        instance->setProperty("AIRPLAYJOINFASTReq", (unsigned long long)jr, 32);
        static const uint8_t jfZero[IEEE80211_ADDR_LEN] = { 0 };
        struct ieee80211_node *jfNode = NULL;
        /* JOINFAST2: JOINFAST never found the BSSID (NoNode 11/11). Record
         * why, and fall back to any scan-table entry with the requested SSID;
         * end_scan -> choose_bss then picks the best one, as it does today. */
        if (memcmp(ad->ad_bssid.octet, jfZero, IEEE80211_ADDR_LEN) == 0) {
            static volatile UInt32 jfBz = 0;
            UInt32 bz = __sync_add_and_fetch(&jfBz, (UInt32)1);
            instance->setProperty("AIRPLAYJOINFASTBssidZero", (unsigned long long)bz, 32);
        } else {
            jfNode = ieee80211_find_node(ic, ad->ad_bssid.octet);
            if (jfNode == NULL) {
                static volatile UInt32 jfBm = 0;
                UInt32 bm = __sync_add_and_fetch(&jfBm, (UInt32)1);
                instance->setProperty("AIRPLAYJOINFASTBssidNotInTable", (unsigned long long)bm, 32);
            }
        }
        if (jfNode != NULL && !(jfNode->ni_chan != NULL &&
            jfNode->ni_chan != IEEE80211_CHAN_ANYC &&
            (UInt32)jfNode->ni_esslen == ad->ad_ssid_len &&
            memcmp(jfNode->ni_essid, ad->ad_ssid, ad->ad_ssid_len) == 0))
            jfNode = NULL;
        if (jfNode == NULL) {
            struct ieee80211_node *jfn;
            UInt32 jfTable = 0;
            RB_FOREACH(jfn, ieee80211_tree, &ic->ic_tree) {
                jfTable++;
                if (jfNode == NULL && jfn->ni_chan != NULL &&
                    jfn->ni_chan != IEEE80211_CHAN_ANYC &&
                    (UInt32)jfn->ni_esslen == ad->ad_ssid_len &&
                    memcmp(jfn->ni_essid, ad->ad_ssid, ad->ad_ssid_len) == 0)
                    jfNode = jfn;
            }
            instance->setProperty("AIRPLAYJOINFASTTableSize", (unsigned long long)jfTable, 32);
            if (jfNode != NULL) {
                static volatile UInt32 jfSs = 0;
                UInt32 ss = __sync_add_and_fetch(&jfSs, (UInt32)1);
                instance->setProperty("AIRPLAYJOINFASTSsidFound", (unsigned long long)ss, 32);
            }
        }
        if (jfNode != NULL) {
            UInt32 nf = __sync_add_and_fetch(&gJoinFastNodeFound, (UInt32)1);
            instance->setProperty("AIRPLAYJOINFASTNodeFound", (unsigned long long)nf, 32);
            instance->setProperty("AIRPLAYJOINFASTLastChan",
                (unsigned long long)ieee80211_chan2ieee(ic, jfNode->ni_chan), 32);
            if (state == IEEE80211_S_SCAN) {
                __sync_lock_test_and_set(&gJoinFastAbortReq, (UInt32)1);
                UInt32 aq = __sync_add_and_fetch(&gJoinFastAbortQueued, (UInt32)1);
                instance->setProperty("AIRPLAYJOINFASTAbortQueued", (unsigned long long)aq, 32);
                ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
            } else {
                UInt32 ns = __sync_add_and_fetch(&gJoinFastNotScanState, (UInt32)1);
                instance->setProperty("AIRPLAYJOINFASTNotScanState", (unsigned long long)ns, 32);
            }
        } else {
            UInt32 nn = __sync_add_and_fetch(&gJoinFastNoNode, (UInt32)1);
            instance->setProperty("AIRPLAYJOINFASTNoNode", (unsigned long long)nn, 32);
        }
    }

    if (state < IEEE80211_S_SCAN) {
        /*
         * Card is in INIT (e.g. init_task reset after a failed scan abort).
         * Target is stored; the scan iwm_init()/iwx_init() starts will match
         * ic_des_essid in ieee80211_end_scan(). Count it so we can see it.
         */
        UInt32 ajb26Skip = __sync_add_and_fetch(
            &gAJB26SkyAssocSkipPreScan, (UInt32)1);
        instance->setProperty(
            "AJB26SkyAssocDeferredInit",
            (unsigned long long)ajb26Skip, 32);
        XYLog("SWITCHFIX: assoc stored while state=%d, will join after init scan\n", state);
        return kIOReturnSuccess;
    }

    if (mustRescan) {
        XYLog("SWITCHFIX: leaving state=%d for new SSID, forcing rescan\n", state);
        instance->setProperty("AJB26SkyAssocForcedRescan",
                              (unsigned long long)1, 32);
        ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
    }
    /* state == SCAN: nothing more; end_scan picks the new ic_des_essid. */
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setDISASSOCIATE(struct apple80211_disassoc_data *ad)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = fHalService->get80211Controller();

    UInt32 ajb26Enter = __sync_add_and_fetch(
        &gAJB26SkyDisassocEnter, (UInt32)1);
    instance->setProperty(
        "AJB26SkyDisassocEnter",
        (unsigned long long)ajb26Enter, 32);
    instance->setProperty(
        "AJB26SkyDisassocLastState",
        (unsigned long long)(UInt32)ic->ic_state, 32);

    if (ic->ic_state < IEEE80211_S_SCAN) {
        UInt32 ajb26Skip = __sync_add_and_fetch(
            &gAJB26SkyDisassocSkipPreScan, (UInt32)1);
        instance->setProperty(
            "AJB26SkyDisassocSkipPreScan",
            (unsigned long long)ajb26Skip, 32);
        return kIOReturnSuccess;
    }

    /*
     * REGFIX: restore the mid-join guard (removed again in the AJBFINAL tree;
     * ASSOC-BUSY-FIX had already put it back once). A DISASSOCIATE that lands
     * during AUTH/ASSOC used to wipe the target SSID and keys
     * (deselect_ess) and abort the join, costing an airportd 10s retry.
     * Switching to a different network mid-join is handled in setASSOCIATE.
     */
    if (ic->ic_state == IEEE80211_S_ASSOC ||
        ic->ic_state == IEEE80211_S_AUTH) {
        UInt32 ajb26Skip = __sync_add_and_fetch(
            &gAJB26SkyDisassocSkipAuthAssoc, (UInt32)1);
        instance->setProperty(
            "AJB26SkyDisassocSkipAuthAssoc",
            (unsigned long long)ajb26Skip, 32);
        UInt32 d = __sync_add_and_fetch(&gJoinDisassocMidJoinIgnored, (UInt32)1);
        instance->setProperty("AIRPLAYJOINDisassocMidJoinIgnored",
                              (unsigned long long)d, 32);
        return kIOReturnSuccess;
    }

    /*
     * DISASSOCFIX: macOS sends DISASSOCIATE 2-3 times for one click on another
     * network (AJB26SkyDisassocEnter +2/+3 per switch). The first one already
     * sent the deauth, reported link down and cleared the target. ic_state only
     * leaves RUN later on the newstate task, so the repeats still saw RUN and
     * did the whole teardown again: second deauth to the old AP while its
     * station was being removed, another SCAN request, RUN-exit cleanup again
     * (AIRPLAYNSRunExitCleanup +2/+3). A repeat is now a no-op.
     * Repeat = voluntary down already latched, link already reported down,
     * no target set, no new join requested since.
     */
    if (gSeqVoluntaryDown &&
        !(instance->currentStatus & kIONetworkLinkActive) &&
        ic->ic_des_esslen == 0 &&
        !gSeqJoinInFlight) {
        UInt32 dup = __sync_add_and_fetch(&gJoinDisassocDuplicateIgnored, (UInt32)1);
        instance->setProperty("AIRPLAYJOINDisassocDuplicateIgnored",
                              (unsigned long long)dup, 32);
        XYLog("DISASSOCFIX: repeat DISASSOCIATE ignored (state=%d)\n", ic->ic_state);
        return kIOReturnSuccess;
    }

    /*
     * JOINGUARD-20261010: a DISASSOCIATE that lands after macOS already asked
     * for the new network (join in flight, new target set) is a stale repeat
     * of the switch's first DISASSOCIATE. The first one already deauthed the
     * old AP and reported link down. Running the teardown again wiped the new
     * target (deselect_ess, +~2 s join restart) and queued new_state(SCAN),
     * which ran after the new link reached RUN and took it down ~50 ms later
     * (SEQShortLivedLinks / involuntary link-down, airportd re-join ~10 s).
     * Counted 1 per switch (JOINDisassocDuringJoin). Now a no-op.
     */
    if (gSeqJoinInFlight && ic->ic_des_esslen != 0) {
        UInt32 dj = __sync_add_and_fetch(&gJoinDisassocDuringJoin, (UInt32)1);
        instance->setProperty("AIRPLAYJOINDisassocDuringJoin",
                              (unsigned long long)dj, 32);
        instance->setProperty("AIRPLAYJOINDisassocDuringJoinIgnored",
                              (unsigned long long)dj, 32);
        XYLog("JOINGUARD: stale DISASSOCIATE during join ignored (state=%d)\n", ic->ic_state);
        return kIOReturnSuccess;
    }

    if (ic->ic_state > IEEE80211_S_AUTH && ic->ic_bss != NULL)
        IEEE80211_SEND_MGMT(ic, ic->ic_bss, IEEE80211_FC0_SUBTYPE_DEAUTH, IEEE80211_REASON_AUTH_LEAVE);
    
    
    disassocIsVoluntary = true;

    /*
     * SEQFIX: report the link down here, synchronously, before returning to
     * airportd (it sends ASSOCIATE ~1 ms later). Previously the link-down came
     * later from the net80211 task, landed mid-join, was treated as
     * "Unexpected link down" and triggered a competing auto-join. The deauth
     * above is already handed to the hardware (send_mgmt calls if_start).
     */
    __sync_lock_test_and_set(&gSeqVoluntaryDown, (UInt32)1);
    gSeqDisassocStampMs = airport_up_time();
    ic->ic_deauth_reason = APPLE80211_REASON_ASSOC_LEAVING;
    if (instance->currentStatus & kIONetworkLinkActive) {
        ieee80211_set_link_state(ic, LINK_STATE_DOWN);
        UInt32 d = __sync_add_and_fetch(&gSeqDisassocSyncDown, (UInt32)1);
        instance->setProperty("AIRPLAYSEQDisassocSyncLinkDown", (unsigned long long)d, 32);
        XYLog("SEQFIX: disassociate - link down reported synchronously\n");
    }

    ieee80211_del_ess(ic, nullptr, 0, 1);
    ieee80211_deselect_ess(ic);
#ifdef USE_APPLE_SUPPLICANT
    ic->ic_rsn_ie_override[1] = 0;
#endif
    ic->ic_assoc_status = APPLE80211_STATUS_UNAVAILABLE;
    ic->ic_deauth_reason = APPLE80211_REASON_ASSOC_LEAVING;
    ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
    return kIOReturnSuccess;
}

/* SONOMA14-CHAN207-V1: experimental native channel table for Sonoma 14.4.
 * Observed IO80211AWDLPeerManager caller clears exactly 10016 bytes and
 * initializes first two u32 fields to 1 before invoking selector 207.
 * This is for that Skywalk ABI; NOT the older 128-entry legacy ioctl ABI.
 * Unidentified native fields are left zero. Do NOT use for other macOS ABIs.
 */
namespace {
struct Sonoma14ChannelsInfo {
    uint32_t version;                 // 0x0000
    uint32_t reserved04;              // 0x0004 (Apple seeds to 1)
    uint32_t reserved08;              // 0x0008
    uint16_t num_chan_specs;          // 0x000c
    uint16_t chan_spec[400];          // 0x000e (unknown native encoding; zeroed)
    uint8_t chan_num[400];            // 0x032e
    uint8_t indoor_restric[400];      // 0x04be (unknown mapping; zeroed)
    uint8_t radar_dfs[400];           // 0x064e
    uint8_t passive[400];             // 0x07de
    uint8_t support_40Mhz[400];       // 0x096e
    uint8_t support_80Mhz[400];       // 0x0afe
    uint8_t alignment[2];            // 0x0c8e
    uint32_t per_chan[400];          // 0x0c90 (unknown semantics; zeroed)
    uint32_t chan_bitmap[400];       // 0x12d0 (unknown semantics; zeroed)
    uint8_t native_tail[3600];       // 0x1910..0x271f (unidentified; zeroed)
} __attribute__((packed));

static_assert(sizeof(Sonoma14ChannelsInfo) == 10016, "Sonoma native channel size");
static_assert(__offsetof(Sonoma14ChannelsInfo, num_chan_specs) == 0x0c, "Sonoma count offset");
static_assert(__offsetof(Sonoma14ChannelsInfo, chan_spec) == 0x0e, "Sonoma spec offset");
static_assert(__offsetof(Sonoma14ChannelsInfo, chan_num) == 0x32e, "Sonoma channel offset");
static_assert(__offsetof(Sonoma14ChannelsInfo, indoor_restric) == 0x4be, "Sonoma indoor offset");
static_assert(__offsetof(Sonoma14ChannelsInfo, radar_dfs) == 0x64e, "Sonoma DFS offset");
static_assert(__offsetof(Sonoma14ChannelsInfo, passive) == 0x7de, "Sonoma passive offset");
static_assert(__offsetof(Sonoma14ChannelsInfo, support_40Mhz) == 0x96e, "Sonoma HT40 offset");
static_assert(__offsetof(Sonoma14ChannelsInfo, support_80Mhz) == 0xafe, "Sonoma VHT80 offset");
static_assert(__offsetof(Sonoma14ChannelsInfo, per_chan) == 0xc90, "Sonoma per-channel offset");
static_assert(__offsetof(Sonoma14ChannelsInfo, chan_bitmap) == 0x12d0, "Sonoma bitmap offset");
static_assert(__offsetof(Sonoma14ChannelsInfo, native_tail) == 0x1910, "Sonoma native tail offset");
} // anonymous namespace

IOReturn AirportItlwmSkywalkInterface::
getCHANNELS_INFO(struct apple80211_channels_info *legacyTypedPointer)
{
    static volatile UInt32 calls = 0;
    UInt32 hits = __sync_add_and_fetch(&calls, 1);
    setProperty("AIRPLAYChanIoctlGet207Calls", (unsigned long long)hits, 32);

    if (!legacyTypedPointer)
        return kIOReturnBadArgument;
    if (!fHalService)
        return kIOReturnNotReady;
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (!ic)
        return kIOReturnNotReady;

    // Apple seeds these two fields to 1 before selector 207. Fail closed
    // for callers with a different header; there is no buffer length here.
    // A matching seed does NOT prove every possible caller has 10016 bytes.
    if (legacyTypedPointer->version != 1 || legacyTypedPointer->unk1 != 1) {
        setProperty("AIRPLAYChanIoctlNative207SeedMismatch", (unsigned long long)1, 8);
        return kIOReturnUnsupported;
    }

    // The native Apple caller is confirmed to allocate 10016 bytes.
    // This method is NOT safe for callers using the old legacy-sized buffer.
    auto *table = reinterpret_cast<Sonoma14ChannelsInfo *>(legacyTypedPointer);
    memset(table, 0, sizeof(*table));
    table->version = 1;
    table->reserved04 = 1;

    unsigned n = 0;
    unsigned nonDfs40 = 0;
    for (int i = 0; i < IEEE80211_CHAN_MAX && n < 400; i++) {
        struct ieee80211_channel *ch = &ic->ic_channels[i];
        if (!ch->ic_freq)
            continue;
        int channelNumber = ieee80211_chan2ieee(ic, ch);
        if (channelNumber <= 0 || channelNumber > 255)
            continue;
        const bool dfs = (ch->ic_flags & IEEE80211_CHAN_DFS) != 0;
        const bool passiveOnly = (ch->ic_flags & IEEE80211_CHAN_PASSIVE) != 0;
        const bool ht40 = IEEE80211_IS_CHAN_HT40(ch) || IEEE80211_IS_CHAN_VHT40(ch);
        const bool vht80 = IEEE80211_IS_CHAN_VHT80(ch);
        table->chan_num[n] = static_cast<uint8_t>(channelNumber);
        table->radar_dfs[n] = dfs ? 1 : 0;
        table->passive[n] = passiveOnly ? 1 : 0;
        table->support_40Mhz[n] = ht40 ? 1 : 0;
        table->support_80Mhz[n] = vht80 ? 1 : 0;
        if (!dfs && !passiveOnly && ht40)
            nonDfs40++;
        n++;
    }
    table->num_chan_specs = static_cast<uint16_t>(n);
    setProperty("AIRPLAYChanIoctlNative207Count", (unsigned long long)n, 32);
    setProperty("AIRPLAYChanIoctlNative207NonDFS40", (unsigned long long)nonDfs40, 32);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getSUPPORTED_CHANNELS(struct apple80211_sup_channel_data *ad)
{
    if (!ad)
        return kIOReturnError;
    ad->version = APPLE80211_VERSION;
    ad->num_channels = 0;
    struct ieee80211com *ic = fHalService->get80211Controller();
    for (int i = 0; i < IEEE80211_CHAN_MAX; i++) {
        if (ic->ic_channels[i].ic_freq != 0) {
            ad->supported_channels[ad->num_channels].channel = ieee80211_chan2ieee(ic, &ic->ic_channels[i]);
            ad->supported_channels[ad->num_channels].flags = ieeeChanFlag2appleScanFlagVentura(ic->ic_channels[i].ic_flags);
            ad->num_channels++;
        }
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getLOCALE(struct apple80211_locale_data *ld)
{
    if (!ld)
        return kIOReturnError;
    ld->version = APPLE80211_VERSION;
    ld->locale  = APPLE80211_LOCALE_FCC;
    
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getDEAUTH(struct apple80211_deauth_data *da)
{
    if (!da)
        return kIOReturnError;
    da->version = APPLE80211_VERSION;
    struct ieee80211com *ic = fHalService->get80211Controller();
    da->deauth_reason = ic->ic_deauth_reason;
//    XYLog("%s, %d\n", __FUNCTION__, da->deauth_reason);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getASSOCIATION_STATUS(struct apple80211_assoc_status_data *hv)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    
    if (!hv)
        return kIOReturnError;
    memset(hv, 0, sizeof(*hv));
    hv->version = APPLE80211_VERSION;
    if (ic->ic_state == IEEE80211_S_RUN)
        hv->status = APPLE80211_STATUS_SUCCESS;
    else
        hv->status = APPLE80211_STATUS_UNAVAILABLE;
//    XYLog("%s, %d\n", __FUNCTION__, hv->status);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setSCANCACHE_CLEAR(void *req)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = fHalService->get80211Controller();
    //if doing background or active scan, don't free nodes.
    if ((ic->ic_flags & IEEE80211_F_BGSCAN) || (ic->ic_flags & IEEE80211_F_ASCAN))
        return kIOReturnSuccess;
    ieee80211_free_allnodes(ic, 0);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setDEAUTH(struct apple80211_deauth_data *da)
{
    XYLog("%s\n", __FUNCTION__);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getMCS(struct apple80211_mcs_data* md)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state != IEEE80211_S_RUN ||  ic->ic_bss == NULL || !md)
        return 6;
    md->version = APPLE80211_VERSION;
    md->index = ic->ic_bss->ni_txmcs;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getLINK_CHANGED_EVENT_DATA(struct apple80211_link_changed_event_data *ed)
{
    if (ed == nullptr)
        return 16;
    
    struct ieee80211com *ic = fHalService->get80211Controller();
    
    bzero(ed, sizeof(apple80211_link_changed_event_data));
    ed->isLinkDown = !(instance->currentStatus & kIONetworkLinkActive);
    if (ed->isLinkDown) {
        /* SEQFIX: latched until the next link up, not cleared by setASSOCIATE */
        /* INVOLFIX: byte 16 is isInvoluntary (airportd: !=0 -> "Unexpected link down", auto-join).
         * Was set to 1 for downs macOS asked for (field misnamed "voluntary"). */
        bool hostRequested = (gSeqVoluntaryDown != 0);
        ed->isInvoluntary = !hostRequested;
        ed->reason = APPLE80211_LINK_DOWN_REASON_DEAUTH;
        ed->subreason = (uint32_t)ic->ic_deauth_reason;
        instance->setProperty("AIRPLAYSEQLastLinkDownInvoluntary",
                              (unsigned long long)(ed->isInvoluntary ? 1 : 0), 32);
        instance->setProperty("AIRPLAYSEQLastLinkDownSubreason",
                              (unsigned long long)ed->subreason, 32);
        if (hostRequested) {
            UInt32 v = __sync_add_and_fetch(&gSeqDownVolReads, (UInt32)1);
            instance->setProperty("AIRPLAYSEQLinkDownVoluntaryReads", (unsigned long long)v, 32);
        } else {
            UInt32 v = __sync_add_and_fetch(&gSeqDownInvolReads, (UInt32)1);
            instance->setProperty("AIRPLAYSEQLinkDownInvoluntaryReads", (unsigned long long)v, 32);
        }
        instance->setProperty("AIRPLAYSEQLastLinkDownVoluntary",
                              (unsigned long long)(hostRequested ? 1 : 0), 32);
        instance->setProperty("AIRPLAYSEQLastDownReason",
                              (unsigned long long)(UInt32)ic->ic_deauth_reason, 32);
    } else
        ed->rssi = -(0 - IWM_MIN_DBM - ic->ic_bss->ni_rssi);
    /* LINKEVTFIX: proves the fixed layout is in the loaded kext (24 = fixed, old = 20) */
    instance->setProperty("AIRPLAYLinkEvtDataSize",
                          (unsigned long long)sizeof(apple80211_link_changed_event_data), 32);
    XYLog("Link %s, reason: %d, subreason: %d, involuntary: %d\n", ed->isLinkDown ? "down" : "up", ed->reason, ed->subreason, ed->isInvoluntary);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setSCAN_REQ(struct apple80211_scan_data *sd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
#if 0
    XYLog("%s Type: %u BSS Type: %u PHY Mode: %u Dwell time: %u Rest time: %u Num channels: %u SSID: %s BSSID: %s\n",
          __FUNCTION__,
          sd->scan_type,
          sd->bss_type,
          sd->phy_mode,
          sd->dwell_time,
          sd->rest_time,
          sd->num_channels,
          sd->ssid,
          ether_sprintf(sd->bssid.octet));
#endif
    /*
     * SCANGUARD: as MILESTONE-REPRO (last build that switched networks well).
     * While macOS is still reading the previous scan's results, refuse the new
     * scan request instead of resetting the result cursor and starting another.
     */
    if (fScanResultWrapping) {
        /*
         * SCANHEAL-20261017: the wrapping latch must be able to self-clear.
         * SCANGUARD refuses a new scan while macOS is still draining the prior
         * results, but if macOS ABANDONS that drain (common during rapid network
         * switching while AWDL is active) the latch would otherwise stick true
         * forever and reject every future scan with 22, wedging Wi-Fi. If the latch
         * has been held longer than a drain could reasonably take, treat it as
         * abandoned: clear it, reset the cursor, and allow this scan. An active
         * drain re-stamps within a few ms, so a live read is never cut off.
         */
        uint64_t heldMs = airport_up_time() - gScanWrapSetMs;
        if (gScanWrapSetMs != 0 && heldMs >= 500) {
            fScanResultWrapping = false;
            fNextNodeToSend = NULL;
            UInt32 h = __sync_add_and_fetch(&gScanHealReset, (UInt32)1);
            instance->setProperty("AIRPLAYSCANHealReset", (unsigned long long)h, 32);
            instance->setProperty("AIRPLAYSCANHealLastHeldMs", (unsigned long long)heldMs, 32);
            /* fall through to normal scan handling below */
        } else {
            UInt32 w = __sync_add_and_fetch(&gScanGuardRejectWrapping, (UInt32)1);
            instance->setProperty("AIRPLAYSCANRejectWrapping", (unsigned long long)w, 32);
            return 22;
        }
    }
    if (ic->ic_state <= IEEE80211_S_INIT) {
        /* SEQFIX: make the "empty network list" wedge visible */
        UInt32 r = __sync_add_and_fetch(&gSeqScanRejectInit, (UInt32)1);
        instance->setProperty("AIRPLAYSCANRejectInit", (unsigned long long)r, 32);
        instance->setProperty("AIRPLAYSCANRejectInitLast", (unsigned long long)1, 32);
        return 22;
    }
    instance->setProperty("AIRPLAYSCANRejectInitLast", (unsigned long long)0, 32);
    if (sd->scan_type == APPLE80211_SCAN_TYPE_FAST || sd->scan_type == APPLE80211_SCAN_TYPE_PASSIVE) {
        if (scanSource) {
            scanSource->setTimeoutMS(100);
            scanSource->enable();
        }
        return kIOReturnSuccess;
    }
    ieee80211_begin_cache_bgscan(&ic->ic_ac.ac_if);
    if (scanSource) {
        scanSource->setTimeoutMS(100);
        scanSource->enable();
    }
    return kIOReturnSuccess;
}

extern OSDictionary *convertScanToDictionary(apple80211_scan_result *a1);

static int convertNodeToScanResult(ItlHalService *fHalService, struct ieee80211_node *fNextNodeToSend, apple80211_scan_result *result)
{
    bzero(result, sizeof(*result));
    result->version = APPLE80211_VERSION;
    if (fNextNodeToSend->ni_rsnie_tlv && fNextNodeToSend->ni_rsnie_tlv_len > 0) {
        result->asr_ie_len = fNextNodeToSend->ni_rsnie_tlv_len;
        memcpy(result->asr_ie_data, fNextNodeToSend->ni_rsnie_tlv, MIN(result->asr_ie_len, sizeof(result->asr_ie_data)));
    } else {
        result->asr_ie_len = 0;
    }
    result->asr_beacon_int = fNextNodeToSend->ni_intval;
    result->asr_nrates = fNextNodeToSend->ni_rates.rs_nrates;
    for (int i = 0; i < result->asr_nrates; i++ )
        result->asr_rates[i] = fNextNodeToSend->ni_rates.rs_rates[i];
    result->asr_age = (uint32_t)(airport_up_time() - fNextNodeToSend->ni_age_ts);
    result->asr_cap = fNextNodeToSend->ni_capinfo;
    result->asr_channel.version = APPLE80211_VERSION;
    result->asr_channel.channel = ieee80211_chan2ieee(fHalService->get80211Controller(), fNextNodeToSend->ni_chan);
    result->asr_channel.flags = ieeeChanFlag2appleScanFlagVentura(fNextNodeToSend->ni_chan->ic_flags);
    result->asr_noise = fHalService->getDriverInfo()->getBSSNoise(); /* NOISEFIX: already dBm (negative), no sign flip */
    result->asr_rssi = -(0 - IWM_MIN_DBM - fNextNodeToSend->ni_rssi);
    memcpy(result->asr_bssid, fNextNodeToSend->ni_bssid, IEEE80211_ADDR_LEN);
    result->asr_ssid_len = fNextNodeToSend->ni_esslen;
    if (result->asr_ssid_len != 0)
        memcpy(&result->asr_ssid, fNextNodeToSend->ni_essid, result->asr_ssid_len);
    return 0;
}

IOReturn AirportItlwmSkywalkInterface::
getCURRENT_NETWORK(apple80211_scan_result *sr)
{
    if (fHalService->get80211Controller()->ic_state != IEEE80211_S_RUN || fHalService->get80211Controller()->ic_bss == NULL)
        return kIOReturnError;
    convertNodeToScanResult(fHalService, fHalService->get80211Controller()->ic_bss, sr);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getCOLOCATED_NETWORK_SCOPE_ID(apple80211_colocated_network_scope_id *as)
{
    if (!as)
        return kIOReturnBadArgument;
    as->version = APPLE80211_VERSION;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getSCAN_RESULT(struct apple80211_scan_result *sr)
{
    if (fNextNodeToSend == NULL) {
        if (fScanResultWrapping) {
            fScanResultWrapping = false;
            return 5;
        } else {
            fNextNodeToSend = RB_MIN(ieee80211_tree, &fHalService->get80211Controller()->ic_tree);
            if (fNextNodeToSend == NULL) {
                return 5;
            }
        }
    } else if (RB_FIND(ieee80211_tree,
                       &fHalService->get80211Controller()->ic_tree,
                       fNextNodeToSend) != fNextNodeToSend) {
        fNextNodeToSend = RB_MIN(ieee80211_tree,
                                &fHalService->get80211Controller()->ic_tree);
        if (fNextNodeToSend == NULL) {
            fScanResultWrapping = false;
            return 5;
        }
    }
//    XYLog("%s ni_bssid=%s ni_essid=%s channel=%d flags=%d asr_cap=%d asr_nrates=%d asr_ssid_len=%d asr_ie_len=%d asr_rssi=%d\n", __FUNCTION__, ether_sprintf(fNextNodeToSend->ni_bssid), fNextNodeToSend->ni_essid, ieee80211_chan2ieee(ic, fNextNodeToSend->ni_chan), ieeeChanFlag2apple(fNextNodeToSend->ni_chan->ic_flags, -1), fNextNodeToSend->ni_capinfo, fNextNodeToSend->ni_rates.rs_nrates, fNextNodeToSend->ni_esslen, fNextNodeToSend->ni_rsnie_tlv == NULL ? 0 : fNextNodeToSend->ni_rsnie_tlv_len, fNextNodeToSend->ni_rssi);
    convertNodeToScanResult(fHalService, fNextNodeToSend, sr);
    
    fNextNodeToSend = RB_NEXT(ieee80211_tree, &HalService->get80211Controller()->ic_tree, fNextNodeToSend);
    if (fNextNodeToSend == NULL) {
        fScanResultWrapping = true;
        gScanWrapSetMs = airport_up_time(); /* SCANHEAL-20261017 */
    }

    return kIOReturnSuccess;
}
