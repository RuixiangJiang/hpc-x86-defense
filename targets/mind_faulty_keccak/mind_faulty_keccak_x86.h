#ifndef MIND_FAULTY_KECCAK_X86_H
#define MIND_FAULTY_KECCAK_X86_H

#include <stdint.h>

#define MFK_HPC_EVENT_COUNT 2u

#define MFK_COUNTER_SET_STRUCTURAL_INSTRUCTIONS 1
#define MFK_COUNTER_SET_STRUCTURAL_BRANCHES 2
#define MFK_COUNTER_SET_STRUCTURAL_BRANCH_MISSES 3
#define MFK_COUNTER_SET_STRUCTURAL_LOADS 4
#define MFK_COUNTER_SET_STRUCTURAL_STORES 5
#define MFK_COUNTER_SET_CACHE_L1D 6
#define MFK_COUNTER_SET_CACHE_L1I 7
#define MFK_COUNTER_SET_CACHE_LLC 8
#define MFK_COUNTER_SET_CACHE_DTLB 9
#define MFK_COUNTER_SET_CACHE_REFERENCES 10
#define MFK_COUNTER_SET_CACHE_MISSES 11
#define MFK_COUNTER_SET_CACHE_L1D_REPLACEMENTS 12
#define MFK_COUNTER_SET_CACHE_L2_REQUEST_MISSES 13
#define MFK_COUNTER_SET_LOAD_L1_HIT 14
#define MFK_COUNTER_SET_LOAD_L2_HIT 15
#define MFK_COUNTER_SET_LOAD_L3_HIT 16
#define MFK_COUNTER_SET_LOAD_L1_MISS 17
#define MFK_COUNTER_SET_LOAD_L2_MISS 18
#define MFK_COUNTER_SET_LOAD_L3_MISS 19
#define MFK_COUNTER_SET_LONG_LATENCY_LOADS 20
#define MFK_COUNTER_SET_STALLS_FRONTEND 21
#define MFK_COUNTER_SET_STALLS_BACKEND 22
#define MFK_COUNTER_SET_STALLS_L1D_MISS 23
#define MFK_COUNTER_SET_STALLS_MEM_ANY 24
#define MFK_COUNTER_SET_RECOVERY_MACHINE_CLEARS 25
#define MFK_COUNTER_SET_RECOVERY_MEMORY_ORDERING 26
#define MFK_COUNTER_SET_RECOVERY_CYCLES 27
#define MFK_COUNTER_SET_RECOVERY_CYCLES_ANY 28

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

void mfk_keccak_target(uint64_t state[25]);
void mfk_measure_target(uint64_t state[25]);
unsigned int mfk_target_rounds(void);
int mfk_skipped_round(void);
unsigned int mfk_abort_rounds(void);
const char *mfk_mode_name(void);
const char *mfk_attack_family(void);

#endif
