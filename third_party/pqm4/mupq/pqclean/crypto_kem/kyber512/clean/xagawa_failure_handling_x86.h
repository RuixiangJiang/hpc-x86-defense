#ifndef PQCLEAN_KYBER512_CLEAN_XAGAWA_FAILURE_HANDLING_X86_H
#define PQCLEAN_KYBER512_CLEAN_XAGAWA_FAILURE_HANDLING_X86_H

#include <stddef.h>
#include <stdint.h>

#define XAGAWA_FAILURE_MODE_BASELINE  0
#define XAGAWA_FAILURE_MODE_SKIP_CMOV 1

#define XAGAWA_FAILURE_HPC_EVENT_COUNT 6

typedef struct {
    uint64_t sequence;
    uint64_t failure_handling_invocations;
    uint64_t time_enabled;
    uint64_t time_running;
    uint64_t values[XAGAWA_FAILURE_HPC_EVENT_COUNT];
    uint32_t valid_mask;
    uint32_t fail_flag;
    uint32_t cmov_len;
    int32_t error_code;
} xagawa_failure_hpc_snapshot;

typedef struct {
    uint32_t fail_flag;
    uint32_t cmov_len;
    uint32_t prekey_preserved;
    uint32_t fallback_applied;
    uint32_t valid;
} xagawa_failure_audit_snapshot;

int PQCLEAN_KYBER512_CLEAN_xagawa_failure_hpc_init(void);
void PQCLEAN_KYBER512_CLEAN_xagawa_failure_hpc_close(void);

void PQCLEAN_KYBER512_CLEAN_xagawa_failure_set_measurement_enabled(
    int enabled);

void PQCLEAN_KYBER512_CLEAN_xagawa_failure_get_hpc_snapshot(
    xagawa_failure_hpc_snapshot *out);

void PQCLEAN_KYBER512_CLEAN_xagawa_failure_get_audit_snapshot(
    xagawa_failure_audit_snapshot *out);

int PQCLEAN_KYBER512_CLEAN_xagawa_failure_build_mode(void);
const char *PQCLEAN_KYBER512_CLEAN_xagawa_failure_mode_name(void);
const char *PQCLEAN_KYBER512_CLEAN_xagawa_failure_event_name(
    unsigned int index);

/*
 * This function replaces only the original Kyber failure-handling cmov call.
 * Verification, H(c), and KDF remain in kem.c and execute normally.
 */
void PQCLEAN_KYBER512_CLEAN_xagawa_failure_handling_apply(
    uint8_t *kr,
    const uint8_t *fallback_z,
    size_t len,
    uint8_t fail);

#endif
