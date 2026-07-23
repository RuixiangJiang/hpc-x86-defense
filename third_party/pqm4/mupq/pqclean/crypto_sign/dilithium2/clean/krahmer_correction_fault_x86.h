#ifndef PQCLEAN_DILITHIUM2_CLEAN_KRAHMER_CORRECTION_FAULT_X86_H
#define PQCLEAN_DILITHIUM2_CLEAN_KRAHMER_CORRECTION_FAULT_X86_H

#include <stdint.h>

#include "polyvec.h"

#define KRAHMER_HPC_MAX_EVENTS 6

#define KRAHMER_COUNTER_SET_STRUCTURAL 0
#define KRAHMER_COUNTER_SET_CACHE_L1D 1
#define KRAHMER_COUNTER_SET_CACHE_LLC_DTLB 2

#define KRAHMER_VARIANT_CORRECTION 1
#define KRAHMER_VARIANT_A_FAULT 2

typedef struct {
    uint64_t sequence;
    uint64_t target_invocations;
    uint64_t time_enabled;
    uint64_t time_running;
    uint64_t values[KRAHMER_HPC_MAX_EVENTS];

    uint32_t valid_mask;
    uint32_t active_event_count;
    uint32_t counter_set;
    uint32_t variant;
    uint32_t attack_build;

    uint32_t target_vec;
    uint32_t target_coeff;
    uint32_t target_row;
    uint32_t target_col;
    uint32_t target_a_coeff;

    int32_t error_code;
} krahmer_hpc_snapshot;

typedef struct {
    uint32_t variant;
    uint32_t attack_build;

    uint32_t target_vec;
    uint32_t target_coeff;
    uint32_t target_row;
    uint32_t target_col;
    uint32_t target_a_coeff;

    int32_t correction_base;
    int32_t correction_term;
    int32_t correction_expected;
    int32_t correction_used;

    int32_t a_original;
    int32_t a_faulty;
    uint32_t matrix_output_mismatches;

    uint32_t fault_requested;
    uint32_t fault_applied;
    uint32_t semantic_valid;
} krahmer_audit_snapshot;

int PQCLEAN_DILITHIUM2_CLEAN_krahmer_hpc_init(void);
void PQCLEAN_DILITHIUM2_CLEAN_krahmer_hpc_close(void);

unsigned int PQCLEAN_DILITHIUM2_CLEAN_krahmer_event_count(void);
const char *PQCLEAN_DILITHIUM2_CLEAN_krahmer_event_name(
    unsigned int index);
const char *PQCLEAN_DILITHIUM2_CLEAN_krahmer_counter_set_name(void);

void PQCLEAN_DILITHIUM2_CLEAN_krahmer_configure(
    unsigned int target_vec,
    unsigned int target_coeff,
    unsigned int target_row,
    unsigned int target_col,
    unsigned int target_a_coeff);

void PQCLEAN_DILITHIUM2_CLEAN_krahmer_set_measurement_enabled(
    int enabled);

void PQCLEAN_DILITHIUM2_CLEAN_krahmer_get_hpc_snapshot(
    krahmer_hpc_snapshot *out);
void PQCLEAN_DILITHIUM2_CLEAN_krahmer_get_audit_snapshot(
    krahmer_audit_snapshot *out);

void PQCLEAN_DILITHIUM2_CLEAN_krahmer_correction_target_baseline(
    int32_t *destination,
    const int32_t *base,
    const int32_t *correction);
void PQCLEAN_DILITHIUM2_CLEAN_krahmer_correction_target_skip(
    int32_t *destination,
    const int32_t *base,
    const int32_t *correction);

void PQCLEAN_DILITHIUM2_CLEAN_krahmer_correction_apply(
    polyvecl *z,
    const polyvecl *y);

void PQCLEAN_DILITHIUM2_CLEAN_krahmer_matrix_prepare(
    polyvecl mat[K]);
void PQCLEAN_DILITHIUM2_CLEAN_krahmer_matrix_region_begin(void);
void PQCLEAN_DILITHIUM2_CLEAN_krahmer_matrix_region_stop(void);
void PQCLEAN_DILITHIUM2_CLEAN_krahmer_matrix_audit(
    const polyveck *out,
    polyvecl mat[K],
    const polyvecl *value);

#endif
