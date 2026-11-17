#ifndef MAC1_S3_RESET_EVIDENCE_HPP
#define MAC1_S3_RESET_EVIDENCE_HPP

#include <stdint.h>

namespace mac1s3reset {

struct Evidence {
    uint32_t resetEpoch;
    uint32_t terminalEpoch;
    uint32_t expectedGeneration;
    uint32_t observedGeneration;

    bool serialized;
    bool masterStopped;
    bool processorResetIssued;
    bool pc1Fault;
    bool commandsQuiescent;
    bool callbacksQuiescent;

    bool eligible() const {
        return resetEpoch != 0 &&
               terminalEpoch == resetEpoch &&
               expectedGeneration != 0 &&
               observedGeneration == expectedGeneration &&
               serialized &&
               masterStopped &&
               processorResetIssued &&
               !pc1Fault &&
               commandsQuiescent &&
               callbacksQuiescent;
    }
};

}
#endif
