#ifndef MIND_FAULTY_KECCAK_X86_H
#define MIND_FAULTY_KECCAK_X86_H

#include <stdint.h>

#define MFK_HPC_EVENT_COUNT 2u

#define MFK_COUNTER_SET_INSTRUCTIONS 1
#define MFK_COUNTER_SET_BRANCHES 2
#define MFK_COUNTER_SET_BRANCH_MISSES 3
#define MFK_COUNTER_SET_LOADS 4
#define MFK_COUNTER_SET_STORES 5

typedef struct {
    uint64_t sequence;
    uint64_t time_enabled;
    uint64_t time_running;
    uint64_t values[MFK_HPC_EVENT_COUNT];
    uint32_t requested_mask;
    uint32_t available_mask;
    uint32_t open_error_mask;
    uint32_t valid_mask;
    int32_t error_code;
} mfk_hpc_snapshot;

int mfk_hpc_init(void);
void mfk_hpc_close(void);
const char *mfk_event_name(unsigned int index);
void mfk_get_hpc_snapshot(mfk_hpc_snapshot *out);

void mfk_keccak_round(uint64_t state[25], unsigned int round);
void mfk_keccak_target(uint64_t state[25]);
void mfk_measure_target(uint64_t state[25]);

#endif
