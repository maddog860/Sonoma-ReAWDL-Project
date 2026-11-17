/* V37: AX210 host-only queue commit admission. This is NOT proof of FW ownership.
 * Must run in the existing main workloop gate, after a valid FW response, before
 * destroying/replacing any host ring. No firmware commands and no DMA operations.
 */
#ifndef MAC1_TVQM_COMMIT_V37_HPP
#define MAC1_TVQM_COMMIT_V37_HPP
#include <stdint.h>
namespace mac1tvqm37 {
enum Decision : uint32_t {
    Fresh = 0, BootstrapQ2 = 1,
    StopOrGeneration = 2, NotSubmitted = 3, InvalidSlot = 4,
    TidAlreadyMapped = 5, OccupiedOrUncertain = 6
};
struct Evidence {
    bool stopping, suspended, generationMatches, submitted;
    bool validQid, tidMapped, previouslyAdopted;
    bool ringCount, queued, desc, cmd, byteCount;
    bool qidInvalid, qidMatchesBootstrap, bootstrapShape, hasOutstandingMbuf;
    bool isQ2, managementUsesQ1;
};
static inline Decision decide(const Evidence& x) {
    if (x.stopping || x.suspended || !x.generationMatches) return StopOrGeneration;
    if (!x.submitted) return NotSubmitted;
    if (!x.validQid) return InvalidSlot;
    if (x.tidMapped) return TidAlreadyMapped;
    if (x.previouslyAdopted) return OccupiedOrUncertain;
    const bool occupied = x.ringCount || x.queued || x.desc || x.cmd || x.byteCount;
    if (!occupied) {
        return x.qidInvalid ? Fresh : OccupiedOrUncertain;
    }
    if (x.isQ2 && x.managementUsesQ1 && x.qidMatchesBootstrap &&
        x.bootstrapShape && !x.queued && !x.hasOutstandingMbuf)
        return BootstrapQ2;
    return OccupiedOrUncertain;
}
}
#endif
