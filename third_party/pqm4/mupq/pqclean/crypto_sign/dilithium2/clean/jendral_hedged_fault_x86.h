#ifndef PQCLEAN_DILITHIUM2_CLEAN_JENDRAL_HEDGED_FAULT_X86_H
#define PQCLEAN_DILITHIUM2_CLEAN_JENDRAL_HEDGED_FAULT_X86_H

#include <stddef.h>
#include <stdint.h>

#include "fips202.h"

#define JENDRAL_HPC_EVENT_COUNT 6

typedef struct {
    uint64_t sequence;
    uint64_t target_invocations;
    uint64_t time_enabled;
    uint64_t time_running;
    uint64_t values[JENDRAL_HPC_EVENT_COUNT];
    uint32_t valid_mask;
    uint32_t attack_build;
    int32_t error_code;
} jendral_hpc_snapshot;

typedef struct {
    uint64_t rnd_tag;
    uint64_t mu_tag;
    uint64_t expected_seed_tag;
    uint64_t used_seed_tag;
    uint64_t public_seed_tag;
    uint32_t rnd_is_public;
    uint32_t final_nonce;
    uint32_t key_absorb_executed;
    uint32_t key_absorb_skipped;
    uint32_t seed_matches_expected;
    uint32_t seed_matches_public;
    uint32_t fault_requested;
    uint32_t fault_applied;
    uint32_t relation_mismatches;
    uint32_t relation_valid;
    uint32_t semantic_valid;
} jendral_audit_snapshot;

int PQCLEAN_DILITHIUM2_CLEAN_jendral_hpc_init(void);
void PQCLEAN_DILITHIUM2_CLEAN_jendral_hpc_close(void);
void PQCLEAN_DILITHIUM2_CLEAN_jendral_set_measurement_enabled(int enabled);
void PQCLEAN_DILITHIUM2_CLEAN_jendral_get_hpc_snapshot(jendral_hpc_snapshot *out);
void PQCLEAN_DILITHIUM2_CLEAN_jendral_get_audit_snapshot(jendral_audit_snapshot *out);
const char *PQCLEAN_DILITHIUM2_CLEAN_jendral_event_name(unsigned int index);

void PQCLEAN_DILITHIUM2_CLEAN_jendral_set_public_randomness(
    const uint8_t rnd[32]);
void PQCLEAN_DILITHIUM2_CLEAN_jendral_clear_public_randomness(void);

int PQCLEAN_DILITHIUM2_CLEAN_jendral_derive_rhoprime(
    uint8_t rhoprime[64],
    const uint8_t key[32],
    const uint8_t mu[64]);

void PQCLEAN_DILITHIUM2_CLEAN_jendral_record_nonce(uint16_t nonce);

int PQCLEAN_DILITHIUM2_CLEAN_jendral_check_single_trace_relation(
    const uint8_t *sig,
    const uint8_t *sk);

/* Named victim operation used by objdump verification. */
void PQCLEAN_DILITHIUM2_CLEAN_jendral_target_key_absorb(
    shake256incctx *state,
    const uint8_t key[32]);

#endif
