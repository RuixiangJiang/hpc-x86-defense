
#ifndef PQCLEAN_DILITHIUM2_CLEAN_RAVI_Z_GENERATION_X86_H
#define PQCLEAN_DILITHIUM2_CLEAN_RAVI_Z_GENERATION_X86_H

#include <stdint.h>
#include "polyvec.h"

/*
 * Paper-exact build modes for Ravi et al., Figure 4:
 *
 * Variant 1: destination aliases the c*s1 operand; attack skips STR.W.
 * Variant 2: destination aliases the y operand;    attack skips STR.W.
 * Variant 3: destination is separate;              attack skips ADD.
 */
#define RAVI_Z_MODE_V1_BASELINE    0
#define RAVI_Z_MODE_V1_SKIP_STORE  1
#define RAVI_Z_MODE_V2_BASELINE    2
#define RAVI_Z_MODE_V2_SKIP_STORE  3
#define RAVI_Z_MODE_V3_BASELINE    4
#define RAVI_Z_MODE_V3_SKIP_ADD    5

#define RAVI_Z_MODE_MIN RAVI_Z_MODE_V1_BASELINE
#define RAVI_Z_MODE_MAX RAVI_Z_MODE_V3_SKIP_ADD

#define RAVI_Z_HPC_EVENT_COUNT 6

typedef struct {
    uint64_t sequence;
    uint64_t generation_invocations;
    uint64_t time_enabled;
    uint64_t time_running;
    uint64_t values[RAVI_Z_HPC_EVENT_COUNT];
    uint32_t valid_mask;
    uint32_t target_vec;
    uint32_t target_coeff;
    int32_t error_code;
} ravi_z_hpc_snapshot;

typedef struct {
    int32_t cs1_before;
    int32_t y_value;
    int32_t z_after;
    uint32_t target_vec;
    uint32_t target_coeff;
    uint32_t valid;
} ravi_z_audit_snapshot;

int PQCLEAN_DILITHIUM2_CLEAN_ravi_z_hpc_init(void);
void PQCLEAN_DILITHIUM2_CLEAN_ravi_z_hpc_close(void);

void PQCLEAN_DILITHIUM2_CLEAN_ravi_z_set_target(unsigned int vec,
                                                 unsigned int coeff);
void PQCLEAN_DILITHIUM2_CLEAN_ravi_z_set_measurement_enabled(int enabled);
void PQCLEAN_DILITHIUM2_CLEAN_ravi_z_set_audit_enabled(int enabled);

void PQCLEAN_DILITHIUM2_CLEAN_ravi_z_get_hpc_snapshot(
    ravi_z_hpc_snapshot *out);
void PQCLEAN_DILITHIUM2_CLEAN_ravi_z_get_audit_snapshot(
    ravi_z_audit_snapshot *out);

const char *PQCLEAN_DILITHIUM2_CLEAN_ravi_z_mode_name(void);
int PQCLEAN_DILITHIUM2_CLEAN_ravi_z_build_mode(void);
const char *PQCLEAN_DILITHIUM2_CLEAN_ravi_z_event_name(unsigned int index);

void PQCLEAN_DILITHIUM2_CLEAN_ravi_z_generation_apply(
    polyvecl *z,
    const polyvecl *y);

#endif
