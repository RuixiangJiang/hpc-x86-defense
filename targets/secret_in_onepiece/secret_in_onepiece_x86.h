#ifndef SECRET_IN_ONEPIECE_X86_H
#define SECRET_IN_ONEPIECE_X86_H

#include <stdint.h>

#define SIO_HPC_EVENT_COUNT 2u
#define SIO_NWORDS 128u
#define SIO_WORD_BITS 16u
#define SIO_TOTAL_INSERTIONS (SIO_NWORDS * SIO_WORD_BITS)
#define SIO_TARGET_WORD 17u
#define SIO_TARGET_BIT 5u
#define SIO_TARGET_LINEAR (SIO_TARGET_WORD * SIO_WORD_BITS + SIO_TARGET_BIT)
#define SIO_TARGET_MASK (1u << SIO_TARGET_BIT)
#define SIO_EXPECTED_SOURCE_BIT 1u
#define SIO_STALE_DESTINATION_BIT 0u

#define SIO_COUNTER_SET_STRUCTURAL_INSTRUCTIONS 1
#define SIO_COUNTER_SET_STRUCTURAL_BRANCHES 2
#define SIO_COUNTER_SET_STRUCTURAL_BRANCH_MISSES 3
#define SIO_COUNTER_SET_STRUCTURAL_LOADS 4
#define SIO_COUNTER_SET_STRUCTURAL_STORES 5
#define SIO_COUNTER_SET_CACHE_L1D 6
#define SIO_COUNTER_SET_CACHE_L1I 7
#define SIO_COUNTER_SET_CACHE_LLC 8
#define SIO_COUNTER_SET_CACHE_DTLB 9
#define SIO_COUNTER_SET_CACHE_REFERENCES 10
#define SIO_COUNTER_SET_CACHE_MISSES 11
#define SIO_COUNTER_SET_CACHE_L1D_REPLACEMENTS 12
#define SIO_COUNTER_SET_CACHE_L2_REQUEST_MISSES 13
#define SIO_COUNTER_SET_LOAD_L1_HIT 14
#define SIO_COUNTER_SET_LOAD_L2_HIT 15
#define SIO_COUNTER_SET_LOAD_L3_HIT 16
#define SIO_COUNTER_SET_LOAD_L1_MISS 17
#define SIO_COUNTER_SET_LOAD_L2_MISS 18
#define SIO_COUNTER_SET_LOAD_L3_MISS 19
#define SIO_COUNTER_SET_LONG_LATENCY_LOADS 20
#define SIO_COUNTER_SET_STALLS_FRONTEND 21
#define SIO_COUNTER_SET_STALLS_BACKEND 22
#define SIO_COUNTER_SET_STALLS_L1D_MISS 23
#define SIO_COUNTER_SET_STALLS_MEM_ANY 24
#define SIO_COUNTER_SET_RECOVERY_MACHINE_CLEARS 25
#define SIO_COUNTER_SET_RECOVERY_MEMORY_ORDERING 26
#define SIO_COUNTER_SET_RECOVERY_CYCLES 27
#define SIO_COUNTER_SET_RECOVERY_CYCLES_ANY 28
#define SIO_COUNTER_SET_UOPS_RETIRED 29
#define SIO_COUNTER_SET_UOPS_ISSUED 30
#define SIO_COUNTER_SET_UOPS_EXECUTED 31
#define SIO_COUNTER_SET_FRONTEND_UOPS_UNDELIVERED 32
#define SIO_COUNTER_SET_FRONTEND_MITE_UOPS 33
#define SIO_COUNTER_SET_FRONTEND_DSB_UOPS 34
#define SIO_COUNTER_SET_FRONTEND_MS_UOPS 35
#define SIO_COUNTER_SET_BRANCH_CONDITIONAL 36
#define SIO_COUNTER_SET_BRANCH_CONDITIONAL_TAKEN 37
#define SIO_COUNTER_SET_BRANCH_CONDITIONAL_NOT_TAKEN 38
#define SIO_COUNTER_SET_BRANCH_MISPRED_CONDITIONAL 39
#define SIO_COUNTER_SET_RESOURCE_STALLS_SCOREBOARD 40
#define SIO_COUNTER_SET_RESOURCE_STALLS_STORE_BUFFER 41
#define SIO_COUNTER_SET_EXECUTION_BOUND_LOADS 42
#define SIO_COUNTER_SET_COUNT 42u

typedef struct {
    uint64_t sequence;
    uint64_t time_enabled;
    uint64_t time_running;
    uint64_t values[SIO_HPC_EVENT_COUNT];
    uint32_t requested_mask;
    uint32_t available_mask;
    uint32_t open_error_mask;
    uint32_t valid_mask;
    int32_t error_code;
} sio_hpc_snapshot;

typedef struct sio_job {
    const uint16_t *share0;
    const uint16_t *share1;
    const uint16_t *initial;
    uint16_t *output;
} sio_job;

typedef void (*sio_target_fn)(sio_job *job);
typedef void (*sio_measure_fn)(sio_job *job);

int sio_select_counter_set(unsigned int counter_set);
int sio_hpc_init(void);
void sio_hpc_close(void);
const char *sio_event_name(unsigned int index);
void sio_get_hpc_snapshot(sio_hpc_snapshot *out);

void sio_decoder_baseline_target(sio_job *job);
void sio_decoder_skip_assignment_target(sio_job *job);
void sio_decoder_skip_or_target(sio_job *job);

void sio_measure_decoder_baseline(sio_job *job);
void sio_measure_decoder_skip_assignment(sio_job *job);
void sio_measure_decoder_skip_or(sio_job *job);

#endif
