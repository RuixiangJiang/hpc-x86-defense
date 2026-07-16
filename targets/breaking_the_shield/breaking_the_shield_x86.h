#ifndef BREAKING_THE_SHIELD_X86_H
#define BREAKING_THE_SHIELD_X86_H

#include <stdint.h>

#define BTS_HPC_EVENT_COUNT 2u
#define BTS_SHAKE256_RATE 136u
#define BTS_SHAKE_FULL_BLOCKS 8u
#define BTS_SHAKE_TAIL_BYTES 37u
#define BTS_SHAKE_INPUT_BYTES (BTS_SHAKE256_RATE * BTS_SHAKE_FULL_BLOCKS + BTS_SHAKE_TAIL_BYTES)
#define BTS_SHAKE_OUTPUT_BYTES 64u
#define BTS_SHAKE_ABORT_AFTER_BLOCKS 4u
#define BTS_SHAKE_SKIP_BLOCK 3u

#define BTS_N 256u
#define BTS_GAMMA1 (1u << 17)
#define BTS_POLYZ_PACKEDBYTES 576u
#define BTS_POLYZ_TARGET_COEFF 17u
#define BTS_POLYZ_TARGET_GROUP (BTS_POLYZ_TARGET_COEFF / 4u)
#define BTS_POLYZ_TARGET_INPUT_BYTE (9u * BTS_POLYZ_TARGET_GROUP + 3u)
#define BTS_POLYZ_STALE_BYTE 0x5au

#define BTS_COUNTER_SET_STRUCTURAL_INSTRUCTIONS 1
#define BTS_COUNTER_SET_STRUCTURAL_BRANCHES 2
#define BTS_COUNTER_SET_STRUCTURAL_BRANCH_MISSES 3
#define BTS_COUNTER_SET_STRUCTURAL_LOADS 4
#define BTS_COUNTER_SET_STRUCTURAL_STORES 5
#define BTS_COUNTER_SET_CACHE_L1D 6
#define BTS_COUNTER_SET_CACHE_L1I 7
#define BTS_COUNTER_SET_CACHE_LLC 8
#define BTS_COUNTER_SET_CACHE_DTLB 9
#define BTS_COUNTER_SET_CACHE_REFERENCES 10
#define BTS_COUNTER_SET_CACHE_MISSES 11
#define BTS_COUNTER_SET_CACHE_L1D_REPLACEMENTS 12
#define BTS_COUNTER_SET_CACHE_L2_REQUEST_MISSES 13
#define BTS_COUNTER_SET_LOAD_L1_HIT 14
#define BTS_COUNTER_SET_LOAD_L2_HIT 15
#define BTS_COUNTER_SET_LOAD_L3_HIT 16
#define BTS_COUNTER_SET_LOAD_L1_MISS 17
#define BTS_COUNTER_SET_LOAD_L2_MISS 18
#define BTS_COUNTER_SET_LOAD_L3_MISS 19
#define BTS_COUNTER_SET_LONG_LATENCY_LOADS 20
#define BTS_COUNTER_SET_STALLS_FRONTEND 21
#define BTS_COUNTER_SET_STALLS_BACKEND 22
#define BTS_COUNTER_SET_STALLS_L1D_MISS 23
#define BTS_COUNTER_SET_STALLS_MEM_ANY 24
#define BTS_COUNTER_SET_RECOVERY_MACHINE_CLEARS 25
#define BTS_COUNTER_SET_RECOVERY_MEMORY_ORDERING 26
#define BTS_COUNTER_SET_RECOVERY_CYCLES 27
#define BTS_COUNTER_SET_RECOVERY_CYCLES_ANY 28
#define BTS_COUNTER_SET_UOPS_RETIRED 29
#define BTS_COUNTER_SET_UOPS_ISSUED 30
#define BTS_COUNTER_SET_UOPS_EXECUTED 31
#define BTS_COUNTER_SET_FRONTEND_UOPS_UNDELIVERED 32
#define BTS_COUNTER_SET_FRONTEND_MITE_UOPS 33
#define BTS_COUNTER_SET_FRONTEND_DSB_UOPS 34
#define BTS_COUNTER_SET_FRONTEND_MS_UOPS 35
#define BTS_COUNTER_SET_BRANCH_CONDITIONAL 36
#define BTS_COUNTER_SET_BRANCH_CONDITIONAL_TAKEN 37
#define BTS_COUNTER_SET_BRANCH_CONDITIONAL_NOT_TAKEN 38
#define BTS_COUNTER_SET_BRANCH_MISPRED_CONDITIONAL 39
#define BTS_COUNTER_SET_RESOURCE_STALLS_SCOREBOARD 40
#define BTS_COUNTER_SET_RESOURCE_STALLS_STORE_BUFFER 41
#define BTS_COUNTER_SET_EXECUTION_BOUND_LOADS 42
#define BTS_COUNTER_SET_COUNT 42u

typedef struct {
    uint64_t sequence;
    uint64_t time_enabled;
    uint64_t time_running;
    uint64_t values[BTS_HPC_EVENT_COUNT];
    uint32_t requested_mask;
    uint32_t available_mask;
    uint32_t open_error_mask;
    uint32_t valid_mask;
    int32_t error_code;
} bts_hpc_snapshot;

typedef union {
    uint8_t shake[BTS_SHAKE_OUTPUT_BYTES];
    int32_t coeffs[BTS_N];
} bts_result;

typedef struct bts_job {
    const uint8_t *input;
    bts_result *output;
    uint32_t fault_register_value;
} bts_job;

typedef void (*bts_target_fn)(bts_job *job);
typedef void (*bts_measure_fn)(bts_job *job);

int bts_select_counter_set(unsigned int counter_set);
int bts_hpc_init(void);
void bts_hpc_close(void);
const char *bts_event_name(unsigned int index);
void bts_get_hpc_snapshot(bts_hpc_snapshot *out);

void bts_shake_baseline_target(bts_job *job);
void bts_shake_abort_target(bts_job *job);
void bts_shake_skip_block_target(bts_job *job);
void bts_polyz_baseline_target(bts_job *job);
void bts_polyz_zero_load_target(bts_job *job);
void bts_polyz_stale_load_target(bts_job *job);
void bts_preload_fault_register(uint32_t value);

void bts_measure_shake_baseline(bts_job *job);
void bts_measure_shake_abort(bts_job *job);
void bts_measure_shake_skip_block(bts_job *job);
void bts_measure_polyz_baseline(bts_job *job);
void bts_measure_polyz_zero_load(bts_job *job);
void bts_measure_polyz_stale_load(bts_job *job);

#endif
