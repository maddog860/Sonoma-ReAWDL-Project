#ifndef MAC1_CMD_RX_BOUNDS_GUARD_HPP
#define MAC1_CMD_RX_BOUNDS_GUARD_HPP
// Host-side bounds policy for the existing LONG_GROUP narrow-command reply
// translation. No side effects, firmware commands, or station-3 authority.
namespace mac1cmdrxguard {
inline bool hostQidReadable(int qid, unsigned hostQueueCount) {
    // Firmware sets the notification bit on unsolicited messages.
    return qid >= 0 && (qid & 0x80) == 0 &&
           static_cast<unsigned>(qid) < hostQueueCount;
}
inline bool slotReadable(int idx, int ringCount) {
    return idx >= 0 && ringCount > 0 && idx < ringCount;
}
}
#endif
