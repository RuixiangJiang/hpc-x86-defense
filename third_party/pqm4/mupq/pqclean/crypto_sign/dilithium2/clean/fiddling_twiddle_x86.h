#ifndef PQCLEAN_DILITHIUM2_CLEAN_FIDDLING_TWIDDLE_X86_H
#define PQCLEAN_DILITHIUM2_CLEAN_FIDDLING_TWIDDLE_X86_H

#include <stdint.h>

#include "polyvec.h"

#define FIDDLE_TWIDDLE_HPC_MAX_EVENTS 6

#define FIDDLE_MODE_BASELINE 0u
#define FIDDLE_MODE_ATTACK 1u

#define FIDDLE_COUNTER_SET_STRUCTURAL 0u
#define FIDDLE_COUNTER_SET_CACHE_L1D 1u
#define FIDDLE_COUNTER_SET_CACHE_LLC_DTLB 2u

typedef struct {
    uint64_t sequence;
    uint64_t signing_invocations;
    uint64_t time_enabled;
    uint64_t time_running;
    uint64_t values[FIDDLE_TWIDDLE_HPC_MAX_EVENTS];

    uint32_t valid_mask;
    uint32_t counter_set;
    uint32_t active_event_count;
    uint32_t target_vec;

    int32_t cpu_before;
    int32_t cpu_after;
    int32_t error_code;
} fiddle_twiddle_hpc_snapshot;

typedef struct {
    uint64_t correct_pointer;
    uint64_t loaded_pointer;
    uint64_t zero_table_pointer;

    int32_t correct_first_twiddle;
    int32_t loaded_first_twiddle;

    uint32_t mode;
    uint32_t target_vec;
    uint32_t twiddles_consumed;
    uint32_t zero_table_verified;
    uint32_t pointer_redirected;
    uint32_t target_ntt_mismatches;
    uint32_t fault_requested;
    uint32_t fault_applied;
    uint32_t semantic_valid;
} fiddle_twiddle_audit_snapshot;

/*
 * Defined in ntt.c while PQCLEAN_DILITHIUM2_FIDDLE_TWIDDLE_X86 is enabled.
 * The original zeta table remains unchanged.
 */
const int32_t *PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_zetas(void);

int PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_set_counter_set(
    unsigned int counter_set);
unsigned int PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_event_count(void);
const char *PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_counter_set_name(void);

int PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_hpc_init(void);
void PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_hpc_close(void);

void PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_configure(
    unsigned int mode,
    unsigned int target_vec);

void PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_set_measurement_enabled(
    int enabled);

void PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_get_hpc_snapshot(
    fiddle_twiddle_hpc_snapshot *out);
void PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_get_audit_snapshot(
    fiddle_twiddle_audit_snapshot *out);

const char *PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_event_name(
    unsigned int index);
const char *PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_mode_name(void);

/*
 * Signing-time replacement for polyvecl_ntt(&z) immediately after z = y.
 * Only target_vec uses the paper-aligned pointer-redirection model.
 */
void PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_polyvecl_ntt(
    polyvecl *value);

/*
 * Visible to objdump verification. The first semantic operation is one
 * RIP-relative load of the active twiddle pointer literal, analogous to the
 * Cortex-M4 ldr r1, [pc, #4]. The complete target NTT then consumes that
 * pointer.
 */
const int32_t *
PQCLEAN_DILITHIUM2_CLEAN_fiddle_ntt_from_pointer_literal(
    int32_t a[N]);

#endif
