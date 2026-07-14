#ifndef PQCLEAN_DILITHIUM2_CLEAN_FIDDLING_TWIDDLE_X86_H
#define PQCLEAN_DILITHIUM2_CLEAN_FIDDLING_TWIDDLE_X86_H

#include <stdint.h>

#include "polyvec.h"

#define FIDDLE_TWIDDLE_HPC_EVENT_COUNT 6

typedef struct {
    uint64_t sequence;
    uint64_t signing_invocations;
    uint64_t time_enabled;
    uint64_t time_running;
    uint64_t values[FIDDLE_TWIDDLE_HPC_EVENT_COUNT];
    uint32_t valid_mask;
    uint32_t target_vec;
    uint32_t target_twiddle_index;
    int32_t error_code;
} fiddle_twiddle_hpc_snapshot;

typedef struct {
    int32_t correct_twiddle;
    int32_t used_twiddle;
    uint32_t target_vec;
    uint32_t target_twiddle_index;
    uint32_t target_len;
    uint32_t target_start;
    uint32_t twiddle_load_skipped;
    uint32_t target_group_mismatches;
    uint32_t final_ntt_mismatches;
    uint32_t fault_requested;
    uint32_t fault_applied;
    uint32_t semantic_valid;
} fiddle_twiddle_audit_snapshot;

/*
 * Defined in ntt.c while PQCLEAN_DILITHIUM2_FIDDLE_TWIDDLE_X86 is enabled.
 * It exposes the implementation's original constant table without copying or
 * altering that table.
 */
const int32_t *PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_zetas(void);

int PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_hpc_init(void);
void PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_hpc_close(void);

void PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_configure(
    unsigned int target_vec,
    unsigned int target_twiddle_index);

void PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_set_measurement_enabled(
    int enabled);

void PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_get_hpc_snapshot(
    fiddle_twiddle_hpc_snapshot *out);

void PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_get_audit_snapshot(
    fiddle_twiddle_audit_snapshot *out);

const char *PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_event_name(
    unsigned int index);

/*
 * Signing-time replacement for polyvecl_ntt(&z) after z = y.
 * Only the selected ephemeral polynomial uses the instrumented NTT.
 */
void PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_polyvecl_ntt(
    polyvecl *value);

/*
 * Named target primitives are intentionally visible to objdump-based checks.
 * The baseline primitive performs the original twiddle load.
 * The attack primitive consumes a stale value and still executes all
 * butterflies in the target group.
 */
void PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_baseline(
    int32_t *a,
    unsigned int len,
    const int32_t *twiddle_pointer);

void PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_skip_load(
    int32_t *a,
    unsigned int len,
    int32_t stale_twiddle);

#endif
