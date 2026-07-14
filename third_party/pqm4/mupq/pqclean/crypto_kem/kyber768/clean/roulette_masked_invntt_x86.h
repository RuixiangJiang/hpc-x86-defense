#ifndef PQCLEAN_KYBER768_CLEAN_ROULETTE_MASKED_INVNTT_X86_H
#define PQCLEAN_KYBER768_CLEAN_ROULETTE_MASKED_INVNTT_X86_H

#include <stdint.h>

#include "params.h"
#include "poly.h"

#define ROULETTE_MODE_BASELINE 0
#define ROULETTE_MODE_SKIP_ADD 1

#define ROULETTE_HPC_EVENT_COUNT 6

typedef struct {
    uint64_t sequence;
    uint64_t reencrypt_invocations;
    uint64_t time_enabled;
    uint64_t time_running;
    uint64_t values[ROULETTE_HPC_EVENT_COUNT];
    uint32_t valid_mask;
    uint32_t target_coeff;
    int32_t error_code;
} roulette_hpc_snapshot;

typedef struct {
    int32_t share_a_before;
    int32_t share_b_before;
    int32_t share_normal_sum;
    int32_t share_used_sum;

    int32_t reference_coeff_mod_q;
    int32_t observed_coeff_mod_q;

    uint32_t target_coeff;
    uint32_t target_changed;
    uint32_t non_target_mismatches;
    uint32_t operation_skipped;

    uint32_t input_v_symbol;
    uint32_t reencrypted_v_symbol;
    uint32_t target_symbol_match;
    uint32_t compare_fail;
    uint32_t oracle_success;
    uint32_t compare_recorded;

    uint32_t valid;
} roulette_audit_snapshot;

int PQCLEAN_KYBER768_CLEAN_roulette_hpc_init(void);
void PQCLEAN_KYBER768_CLEAN_roulette_hpc_close(void);

void PQCLEAN_KYBER768_CLEAN_roulette_set_target(
    unsigned int target_coeff);
void PQCLEAN_KYBER768_CLEAN_roulette_set_measurement_enabled(
    int enabled);
void PQCLEAN_KYBER768_CLEAN_roulette_set_reencrypt_active(
    int active);
void PQCLEAN_KYBER768_CLEAN_roulette_set_mask_seed(
    uint32_t seed);

void PQCLEAN_KYBER768_CLEAN_roulette_get_hpc_snapshot(
    roulette_hpc_snapshot *out);
void PQCLEAN_KYBER768_CLEAN_roulette_get_audit_snapshot(
    roulette_audit_snapshot *out);

int PQCLEAN_KYBER768_CLEAN_roulette_build_mode(void);
const char *PQCLEAN_KYBER768_CLEAN_roulette_mode_name(void);
const char *PQCLEAN_KYBER768_CLEAN_roulette_event_name(
    unsigned int index);

void PQCLEAN_KYBER768_CLEAN_roulette_masked_invntt_apply(
    poly *v);

void PQCLEAN_KYBER768_CLEAN_roulette_record_compare(
    const uint8_t input_ct[KYBER_CIPHERTEXTBYTES],
    const uint8_t reencrypted_ct[KYBER_CIPHERTEXTBYTES],
    int compare_fail);

#endif
