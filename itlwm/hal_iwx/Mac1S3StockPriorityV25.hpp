#pragma once
/* Firmware writes must be deliberately enabled by BOTH independently
 * reviewed switches before the experimental command admission lease is
 * allowed to affect even one ordinary AX210 firmware command. In the
 * current compile-locked build, the stock path runs without this lease.
 */
namespace mac1s3stockpriority {
inline constexpr bool enableLease(bool supported, bool s7WriteApproved,
                                  bool v3WriteApproved) {
    return supported && s7WriteApproved && v3WriteApproved;
}
inline constexpr bool rejectUnreviewedS3(bool isS3Command,
                                         bool leaseEnabled) {
    return isS3Command && !leaseEnabled;
}
} // namespace mac1s3stockpriority
