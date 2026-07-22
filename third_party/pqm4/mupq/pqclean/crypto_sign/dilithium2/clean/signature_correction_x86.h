#ifndef PQCLEAN_DILITHIUM2_CLEAN_SIGNATURE_CORRECTION_X86_H
#define PQCLEAN_DILITHIUM2_CLEAN_SIGNATURE_CORRECTION_X86_H

#include <stdint.h>

#include "polyvec.h"

#define SIGNCORR_HPC_MAX_EVENTS 6
#define SIGNCORR_HPC_EVENT_COUNT SIGNCORR_HPC_MAX_EVENTS

typedef struct {
    uint64_t sequence;
    uint64_t signing_invocations;
    uint64_t time_enabled;
    uint64_t time_running;
    uint64_t values[SIGNCORR_HPC_EVENT_COUNT];
    uint32_t valid_mask;
    uint32_t target_vec;
    uint32_t target_coeff;
    uint32_t bit_index;
    int32_t error_code;
} signcorr_hpc_snapshot;

typedef struct {
    int32_t original_value;
    int32_t faulty_value;
    uint32_t original_word;
    uint32_t faulty_word;
    uint32_t xor_mask;
    uint32_t target_vec;
    uint32_t target_coeff;
    uint32_t bit_index;
    uint32_t original_bit;
    uint32_t faulty_bit;
    uint32_t hamming_distance;
    uint32_t fault_requested;
    uint32_t fault_applied;
    uint32_t valid;
} signcorr_audit_snapshot;

int PQCLEAN_DILITHIUM2_CLEAN_signcorr_set_counter_set(
    unsigned int counter_set);
unsigned int PQCLEAN_DILITHIUM2_CLEAN_signcorr_event_count(void);
const char *PQCLEAN_DILITHIUM2_CLEAN_signcorr_counter_set_name(void);

int PQCLEAN_DILITHIUM2_CLEAN_signcorr_hpc_init(void);
void PQCLEAN_DILITHIUM2_CLEAN_signcorr_hpc_close(void);

void PQCLEAN_DILITHIUM2_CLEAN_signcorr_configure(
    int fault_enable,
    unsigned int target_vec,
    unsigned int target_coeff,
    unsigned int bit_index);

void PQCLEAN_DILITHIUM2_CLEAN_signcorr_set_measurement_enabled(
    int enabled);

void PQCLEAN_DILITHIUM2_CLEAN_signcorr_get_hpc_snapshot(
    signcorr_hpc_snapshot *out);

void PQCLEAN_DILITHIUM2_CLEAN_signcorr_get_audit_snapshot(
    signcorr_audit_snapshot *out);

const char *PQCLEAN_DILITHIUM2_CLEAN_signcorr_event_name(
    unsigned int index);

void PQCLEAN_DILITHIUM2_CLEAN_signcorr_prepare_and_measure_s1(
    polyvecl *s1);

#endif
