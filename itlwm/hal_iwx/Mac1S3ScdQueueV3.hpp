#pragma once
/* SCD_QUEUE_CONFIG_CMD v3 firmware ABI.
 * No command submission, queue ownership, or DMA authorization.
 */
#include <stddef.h>
#include <stdint.h>

namespace mac1s3scdv3 {

static const uint8_t kGroup = 0x05;
static const uint8_t kOpcode = 0x17;
static const uint8_t kCommandVersion = 3;

static const uint32_t kAdd = 0;
static const uint32_t kRemove = 1;
static const uint32_t kModify = 2;

#pragma pack(push, 1)

struct Add {
    uint32_t sta_mask;
    uint8_t tid;
    uint8_t reserved[3];
    uint32_t flags;
    uint32_t cb_size;
    uint64_t bc_dram_addr;
    uint64_t tfdq_dram_addr;
};

struct Remove {
    uint32_t sta_mask;
    uint32_t tid;
};

struct Modify {
    uint32_t old_sta_mask;
    uint32_t tid;
    uint32_t new_sta_mask;
};

struct Command {
    uint32_t operation;
    union {
        Add add;
        Remove remove;
        Modify modify;
    } u;
};

#pragma pack(pop)

static_assert(sizeof(Add) == 32, "ADD ABI mismatch");
static_assert(sizeof(Remove) == 8, "REMOVE ABI mismatch");
static_assert(sizeof(Modify) == 12, "MODIFY ABI mismatch");
static_assert(sizeof(Command) == 36, "Command ABI mismatch");

static_assert(offsetof(Command, u.add.sta_mask) == 4, "station mask");
static_assert(offsetof(Command, u.add.tid) == 8, "TID");
static_assert(offsetof(Command, u.add.flags) == 12, "flags");
static_assert(offsetof(Command, u.add.cb_size) == 16, "buffer size");
static_assert(offsetof(Command, u.add.bc_dram_addr) == 20, "BC DMA");
static_assert(offsetof(Command, u.add.tfdq_dram_addr) == 28, "TFD DMA");

}
