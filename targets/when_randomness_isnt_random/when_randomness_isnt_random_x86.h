#ifndef WHEN_RANDOMNESS_ISNT_RANDOM_X86_H
#define WHEN_RANDOMNESS_ISNT_RANDOM_X86_H

#include <stdint.h>

#define WRIR_HPC_EVENT_COUNT 2u

#define WRIR_COUNTER_INSTRUCTIONS 1
#define WRIR_COUNTER_RETIRED_LOADS 2
#define WRIR_COUNTER_RETIRED_STORES 3
#define WRIR_COUNTER_L1D_MISSES 4
#define WRIR_COUNTER_LLC_MISSES 5
#define WRIR_COUNTER_DTLB_MISSES 6
#define WRIR_COUNTER_CACHE_REFERENCES 7
#define WRIR_COUNTER_CACHE_MISSES 8

typedef struct {
    const uint8_t *correct;
    const uint8_t *fault;
} wrir_pointer_frame;

typedef struct {
    uint64_t time_enabled;
    uint64_t time_running;
    uint64_t values[WRIR_HPC_EVENT_COUNT];
    uint32_t requested_mask;
    uint32_t available_mask;
    uint32_t valid_mask;
    int32_t error_code;
} wrir_hpc_snapshot;

int wrir_hpc_init(void);
void wrir_hpc_close(void);
const char *wrir_event_name(unsigned int index);
void wrir_get_hpc_snapshot(wrir_hpc_snapshot *out);

void wrir_target(const void *input, void *output);
void wrir_measure_target(const void *input, void *output);

#endif
