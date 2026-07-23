#ifndef BREAKING_THE_SHIELD_X86_H
#define BREAKING_THE_SHIELD_X86_H

#include <stdint.h>

#define BTS_HPC_EVENT_COUNT 2u

#define BTS_SHAKE256_RATE 136u
#define BTS_SHAKE_FULL_BLOCKS 8u
#define BTS_SHAKE_ABORT_AFTER_BLOCKS 4u
#define BTS_SHAKE_TAIL_BYTES 37u
#define BTS_SHAKE_INPUT_BYTES \
    (BTS_SHAKE256_RATE * BTS_SHAKE_FULL_BLOCKS + BTS_SHAKE_TAIL_BYTES)
#define BTS_SHAKE_OUTPUT_BYTES 64u

#define BTS_GAMMA1 (1u << 17)
#define BTS_POLYZ_GROUP_BYTES 9u

typedef union {
    uint8_t shake[BTS_SHAKE_OUTPUT_BYTES];
    int32_t coefficient;
} bts_result;

typedef struct {
    const uint8_t *input;
    bts_result *output;
} bts_job;

typedef struct {
    uint64_t time_enabled;
    uint64_t time_running;
    uint64_t values[BTS_HPC_EVENT_COUNT];
    uint32_t requested_mask;
    uint32_t available_mask;
    uint32_t valid_mask;
    int32_t error_code;
} bts_hpc_snapshot;

int bts_hpc_init(void);
void bts_hpc_close(void);
const char *bts_event_name(unsigned int index);
void bts_get_hpc_snapshot(bts_hpc_snapshot *out);

void bts_target(bts_job *job);
void bts_measure_target(bts_job *job);

/* Called by the hand-written Region-1 control-flow target. */
void bts_absorb_full_block_entry(
    uint64_t state[25],
    const uint8_t block[BTS_SHAKE256_RATE]);
void bts_absorb_tail_entry(
    uint8_t output[BTS_SHAKE_OUTPUT_BYTES],
    uint64_t state[25],
    const uint8_t tail[BTS_SHAKE_TAIL_BYTES]);

void bts_reference_shake(
    uint8_t output[BTS_SHAKE_OUTPUT_BYTES],
    const uint8_t input[BTS_SHAKE_INPUT_BYTES],
    unsigned int full_blocks);
int32_t bts_reference_polyz_coefficient(
    const uint8_t packed_group[BTS_POLYZ_GROUP_BYTES],
    int skipped_load);

#endif
