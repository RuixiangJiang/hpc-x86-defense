#ifndef PQCLEAN_DILITHIUM2_CLEAN_RAVI_NNUO_X86_H
#define PQCLEAN_DILITHIUM2_CLEAN_RAVI_NNUO_X86_H

#include <stdint.h>

#include "params.h"
#include "polyvec.h"

#define NNUO_X86_MODE_BASELINE       0
#define NNUO_X86_MODE_SKIP_INCREMENT 1

#define NNUO_X86_EVENT_COUNT 6
#define NNUO_X86_TOTAL_CALLS ((unsigned int)(L + K))

typedef struct {
    uint64_t sequence;
    uint64_t sampling_invocations;
    uint64_t time_enabled;
    uint64_t time_running;
    uint64_t values[NNUO_X86_EVENT_COUNT];
    uint32_t valid_mask;
    uint32_t target_call;
    int32_t error_code;
} nnuo_x86_hpc_snapshot;

typedef struct {
    uint16_t used_nonces[NNUO_X86_TOTAL_CALLS];
    uint16_t expected_nonce_target;
    uint16_t used_nonce_target;
    int32_t duplicate_call;
    uint32_t nonce_progress_errors;
    uint32_t target_call;
    uint32_t duplicate_output_equal;
    uint32_t valid;
} nnuo_x86_audit_snapshot;

int PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_hpc_init(void);
void PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_hpc_close(void);

void PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_set_target(unsigned int target_call);
void PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_set_measurement_enabled(int enabled);
void PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_set_audit_enabled(int enabled);

void PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_get_hpc_snapshot(
    nnuo_x86_hpc_snapshot *out);
void PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_get_audit_snapshot(
    nnuo_x86_audit_snapshot *out);

int PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_build_mode(void);
const char *PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_mode_name(void);
const char *PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_event_name(
    unsigned int index);

int PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_sample_secret_vectors(
    polyvecl *s1,
    polyveck *s2,
    const uint8_t seed[CRHBYTES]);

#endif
