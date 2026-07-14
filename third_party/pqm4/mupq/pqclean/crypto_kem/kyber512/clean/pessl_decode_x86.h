#ifndef PQCLEAN_KYBER512_CLEAN_PESSL_DECODE_X86_H
#define PQCLEAN_KYBER512_CLEAN_PESSL_DECODE_X86_H

#include <stdint.h>

#include "params.h"
#include "poly.h"

#define PESSL_DECODE_MODE_BASELINE   0
#define PESSL_DECODE_MODE_SKIP_SHIFT 1

#define PESSL_DECODE_HPC_EVENT_COUNT 6

typedef struct {
    uint64_t sequence;
    uint64_t decode_invocations;
    uint64_t time_enabled;
    uint64_t time_running;
    uint64_t values[PESSL_DECODE_HPC_EVENT_COUNT];
    uint32_t valid_mask;
    uint32_t target_coeff;
    int32_t error_code;
} pessl_decode_hpc_snapshot;

typedef struct {
    int32_t raw_coefficient;
    uint32_t normalized_coefficient;
    uint32_t normal_bit;
    uint32_t fault_bit;
    uint32_t observed_bit;
    uint32_t target_coeff;
    uint32_t valid;
} pessl_decode_audit_snapshot;

int PQCLEAN_KYBER512_CLEAN_pessl_decode_hpc_init(void);
void PQCLEAN_KYBER512_CLEAN_pessl_decode_hpc_close(void);

void PQCLEAN_KYBER512_CLEAN_pessl_decode_set_target(
    unsigned int target_coeff);
void PQCLEAN_KYBER512_CLEAN_pessl_decode_set_measurement_enabled(
    int enabled);

void PQCLEAN_KYBER512_CLEAN_pessl_decode_get_hpc_snapshot(
    pessl_decode_hpc_snapshot *out);
void PQCLEAN_KYBER512_CLEAN_pessl_decode_get_audit_snapshot(
    pessl_decode_audit_snapshot *out);

int PQCLEAN_KYBER512_CLEAN_pessl_decode_build_mode(void);
const char *PQCLEAN_KYBER512_CLEAN_pessl_decode_mode_name(void);
const char *PQCLEAN_KYBER512_CLEAN_pessl_decode_event_name(
    unsigned int index);

void PQCLEAN_KYBER512_CLEAN_pessl_decode_apply(
    uint8_t msg[KYBER_INDCPA_MSGBYTES],
    const poly *a);

#endif
