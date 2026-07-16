#ifndef PQCLEAN_KYBER768_CLEAN_ROULETTE_MASKED_INVNTT_X86_H
#define PQCLEAN_KYBER768_CLEAN_ROULETTE_MASKED_INVNTT_X86_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

#define ROU_MODE_BASELINE 0u
#define ROU_MODE_SKIP_LOCAL_OPERATION 1u
#define ROU_MODE_SET_CONSTANT 2u
#define ROU_MODE_SET_RANDOM 3u
#define ROU_MODE_FLIP_BIT 4u
#define ROU_HPC_EVENT_COUNT 2u

#define ROU_COUNTER_SET_STRUCTURAL_INSTRUCTIONS 1
#define ROU_COUNTER_SET_STRUCTURAL_BRANCHES 2
#define ROU_COUNTER_SET_STRUCTURAL_BRANCH_MISSES 3
#define ROU_COUNTER_SET_STRUCTURAL_LOADS 4
#define ROU_COUNTER_SET_STRUCTURAL_STORES 5
#define ROU_COUNTER_SET_CACHE_L1D 6
#define ROU_COUNTER_SET_CACHE_L1I 7
#define ROU_COUNTER_SET_CACHE_LLC 8
#define ROU_COUNTER_SET_CACHE_DTLB 9
#define ROU_COUNTER_SET_CACHE_REFERENCES 10
#define ROU_COUNTER_SET_CACHE_MISSES 11
#define ROU_COUNTER_SET_CACHE_L1D_REPLACEMENTS 12
#define ROU_COUNTER_SET_CACHE_L2_REQUEST_MISSES 13
#define ROU_COUNTER_SET_LOAD_L1_HIT 14
#define ROU_COUNTER_SET_LOAD_L2_HIT 15
#define ROU_COUNTER_SET_LOAD_L3_HIT 16
#define ROU_COUNTER_SET_LOAD_L1_MISS 17
#define ROU_COUNTER_SET_LOAD_L2_MISS 18
#define ROU_COUNTER_SET_LOAD_L3_MISS 19
#define ROU_COUNTER_SET_LONG_LATENCY_LOADS 20
#define ROU_COUNTER_SET_STALLS_FRONTEND 21
#define ROU_COUNTER_SET_STALLS_BACKEND 22
#define ROU_COUNTER_SET_STALLS_L1D_MISS 23
#define ROU_COUNTER_SET_STALLS_MEM_ANY 24
#define ROU_COUNTER_SET_RECOVERY_MACHINE_CLEARS 25
#define ROU_COUNTER_SET_RECOVERY_MEMORY_ORDERING 26
#define ROU_COUNTER_SET_RECOVERY_CYCLES 27
#define ROU_COUNTER_SET_RECOVERY_CYCLES_ANY 28
#define ROU_COUNTER_SET_UOPS_RETIRED 29
#define ROU_COUNTER_SET_UOPS_ISSUED 30
#define ROU_COUNTER_SET_UOPS_EXECUTED 31
#define ROU_COUNTER_SET_FRONTEND_UOPS_UNDELIVERED 32
#define ROU_COUNTER_SET_FRONTEND_MITE_UOPS 33
#define ROU_COUNTER_SET_FRONTEND_DSB_UOPS 34
#define ROU_COUNTER_SET_FRONTEND_MS_UOPS 35
#define ROU_COUNTER_SET_BRANCH_CONDITIONAL 36
#define ROU_COUNTER_SET_BRANCH_CONDITIONAL_TAKEN 37
#define ROU_COUNTER_SET_BRANCH_CONDITIONAL_NOT_TAKEN 38
#define ROU_COUNTER_SET_BRANCH_MISPRED_CONDITIONAL 39
#define ROU_COUNTER_SET_RESOURCE_STALLS_SCOREBOARD 40
#define ROU_COUNTER_SET_RESOURCE_STALLS_STORE_BUFFER 41
#define ROU_COUNTER_SET_EXECUTION_BOUND_LOADS 42
#define ROU_COUNTER_SET_COUNT 42u

typedef struct {
    uint64_t sequence;
    uint64_t time_enabled;
    uint64_t time_running;
    uint64_t values[ROU_HPC_EVENT_COUNT];
    uint32_t requested_mask;
    uint32_t available_mask;
    uint32_t open_error_mask;
    uint32_t valid_mask;
    int32_t error_code;
} rou_hpc_snapshot;

typedef struct {
    int32_t share_a_before;
    int32_t share_b_before;
    int32_t normal_intermediate;
    int32_t used_intermediate;
    int32_t selected_constant;
    int32_t selected_random;
    int32_t reference_coeff_mod_q;
    int32_t observed_coeff_mod_q;
    uint64_t reference_output_tag;
    uint64_t observed_output_tag;
    uint32_t mode;
    uint32_t target_coeff;
    uint32_t flip_bit;
    uint32_t flip_mask;
    uint32_t target_changed;
    uint32_t non_target_mismatches;
    uint32_t operation_skipped;
    uint32_t constant_replacement;
    uint32_t random_replacement;
    uint32_t bit_flipped;
    uint32_t fault_applied;
    uint32_t input_v_symbol;
    uint32_t reencrypted_v_symbol;
    uint32_t target_symbol_match;
    uint32_t compare_fail;
    uint32_t oracle_success;
    uint32_t compare_recorded;
    uint32_t valid;
} rou_audit_snapshot;

int rou_select_counter_set(unsigned int counter_set);
int rou_hpc_init(void);
void rou_hpc_close(void);
const char *rou_event_name(unsigned int index);
void rou_get_hpc_snapshot(rou_hpc_snapshot *out);

int PQCLEAN_KYBER768_CLEAN_roulette_set_mode(unsigned int mode);
const char *PQCLEAN_KYBER768_CLEAN_roulette_mode_name(void);
void PQCLEAN_KYBER768_CLEAN_roulette_set_target(unsigned int target_coeff);
void PQCLEAN_KYBER768_CLEAN_roulette_set_measurement_enabled(int enabled);
void PQCLEAN_KYBER768_CLEAN_roulette_set_reencrypt_active(int active);
void PQCLEAN_KYBER768_CLEAN_roulette_set_mask_seed(uint32_t seed);
void PQCLEAN_KYBER768_CLEAN_roulette_set_fault_seed(uint32_t seed);
void PQCLEAN_KYBER768_CLEAN_roulette_set_constant(int32_t value);
int PQCLEAN_KYBER768_CLEAN_roulette_set_flip_bit(unsigned int bit);
void PQCLEAN_KYBER768_CLEAN_roulette_get_audit_snapshot(
    rou_audit_snapshot *out);
void PQCLEAN_KYBER768_CLEAN_roulette_masked_invntt_apply(poly *v);
void PQCLEAN_KYBER768_CLEAN_roulette_record_compare(
    const uint8_t input_ct[KYBER_CIPHERTEXTBYTES],
    const uint8_t reencrypted_ct[KYBER_CIPHERTEXTBYTES],
    int compare_fail);

int32_t rou_target_masked_add_baseline(int32_t, int32_t, int32_t, uint32_t);
int32_t rou_target_skip_local_masked_operation(int32_t, int32_t, int32_t, uint32_t);
int32_t rou_target_set_masked_intermediate_constant(int32_t, int32_t, int32_t, uint32_t);
int32_t rou_target_replace_masked_intermediate_random(int32_t, int32_t, int32_t, uint32_t);
int32_t rou_target_flip_masked_intermediate_bit(int32_t, int32_t, int32_t, uint32_t);
int32_t rou_measure_masked_add_baseline(int32_t, int32_t, int32_t, uint32_t);
int32_t rou_measure_skip_local_masked_operation(int32_t, int32_t, int32_t, uint32_t);
int32_t rou_measure_set_masked_intermediate_constant(int32_t, int32_t, int32_t, uint32_t);
int32_t rou_measure_replace_masked_intermediate_random(int32_t, int32_t, int32_t, uint32_t);
int32_t rou_measure_flip_masked_intermediate_bit(int32_t, int32_t, int32_t, uint32_t);

#endif
