#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "secret_in_onepiece_x86.h"
#include "microarch_events_generated.h"

#include <errno.h>
#include <linux/perf_event.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SIO_PMU_TYPE
#define SIO_PMU_TYPE 4u
#endif

#ifndef SIO_LOAD_CONFIG
#define SIO_LOAD_CONFIG UINT64_C(0x81d0)
#endif

#ifndef SIO_STORE_CONFIG
#define SIO_STORE_CONFIG UINT64_C(0x82d0)
#endif



#if defined(__GNUC__) || defined(__clang__)
#define SIO_NOINLINE __attribute__((noinline, noclone, used))
#else
#define SIO_NOINLINE
#endif

typedef struct {
    const char *name;
    uint32_t type;
    uint64_t config;
    uint64_t config1;
    uint64_t config2;
    uint32_t precise_ip;
    uint32_t available;
} sio_event_desc;

#define SIO_EVENT_GENERIC(name_, config_) \
    {name_, PERF_TYPE_HARDWARE, config_, UINT64_C(0), UINT64_C(0), 0u, 1u}

#define SIO_EVENT_RAW(name_, macro_) \
    { \
        name_, \
        SIO_EVT_##macro_##_TYPE, \
        SIO_EVT_##macro_##_CONFIG, \
        SIO_EVT_##macro_##_CONFIG1, \
        SIO_EVT_##macro_##_CONFIG2, \
        SIO_EVT_##macro_##_PRECISE_IP, \
        SIO_EVT_##macro_##_AVAILABLE \
    }

#define SIO_CACHE_CONFIG(cache, op, result) \
    ((uint64_t)(cache) | ((uint64_t)(op) << 8) | ((uint64_t)(result) << 16))

/*
 * Retained only as a readable mapping from the previous compile-time build.
 * The active table below selects the same events at runtime so every
 * baseline, attack, and PMU pass uses exactly one ELF executable.
 */
#if 0
#if SIO_COUNTER_SET == SIO_COUNTER_SET_STRUCTURAL_INSTRUCTIONS
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_GENERIC("instructions", PERF_COUNT_HW_INSTRUCTIONS),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_STRUCTURAL_BRANCHES
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_GENERIC("branches", PERF_COUNT_HW_BRANCH_INSTRUCTIONS),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_STRUCTURAL_BRANCH_MISSES
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_GENERIC("branch_misses", PERF_COUNT_HW_BRANCH_MISSES),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_STRUCTURAL_LOADS
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"retired_loads", SIO_PMU_TYPE, SIO_LOAD_CONFIG, 0, 0, 0, 1},
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_STRUCTURAL_STORES
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"retired_stores", SIO_PMU_TYPE, SIO_STORE_CONFIG, 0, 0, 0, 1},
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_CACHE_L1D
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"l1d_read_misses", PERF_TYPE_HW_CACHE,
        SIO_CACHE_CONFIG(PERF_COUNT_HW_CACHE_L1D, PERF_COUNT_HW_CACHE_OP_READ,
                         PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_CACHE_L1I
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"l1i_read_misses", PERF_TYPE_HW_CACHE,
        SIO_CACHE_CONFIG(PERF_COUNT_HW_CACHE_L1I, PERF_COUNT_HW_CACHE_OP_READ,
                         PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_CACHE_LLC
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"llc_read_misses", PERF_TYPE_HW_CACHE,
        SIO_CACHE_CONFIG(PERF_COUNT_HW_CACHE_LL, PERF_COUNT_HW_CACHE_OP_READ,
                         PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_CACHE_DTLB
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"dtlb_read_misses", PERF_TYPE_HW_CACHE,
        SIO_CACHE_CONFIG(PERF_COUNT_HW_CACHE_DTLB, PERF_COUNT_HW_CACHE_OP_READ,
                         PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_CACHE_REFERENCES
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_GENERIC("cache_references", PERF_COUNT_HW_CACHE_REFERENCES),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_CACHE_MISSES
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_GENERIC("cache_misses", PERF_COUNT_HW_CACHE_MISSES),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_CACHE_L1D_REPLACEMENTS
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("l1d_replacements", L1D_REPLACEMENTS),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_CACHE_L2_REQUEST_MISSES
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("l2_request_misses", L2_REQUEST_MISSES),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_LOAD_L1_HIT
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("load_l1_hit", LOAD_L1_HIT),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_LOAD_L2_HIT
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("load_l2_hit", LOAD_L2_HIT),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_LOAD_L3_HIT
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("load_l3_hit", LOAD_L3_HIT),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_LOAD_L1_MISS
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("load_l1_miss", LOAD_L1_MISS),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_LOAD_L2_MISS
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("load_l2_miss", LOAD_L2_MISS),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_LOAD_L3_MISS
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("load_l3_miss", LOAD_L3_MISS),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_LONG_LATENCY_LOADS
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("long_latency_loads", LONG_LATENCY_LOADS),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_STALLS_FRONTEND
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_GENERIC("stalled_frontend_cycles", PERF_COUNT_HW_STALLED_CYCLES_FRONTEND),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_STALLS_BACKEND
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_GENERIC("stalled_backend_cycles", PERF_COUNT_HW_STALLED_CYCLES_BACKEND),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_STALLS_L1D_MISS
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("stalls_l1d_miss", STALLS_L1D_MISS),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_STALLS_MEM_ANY
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("stalls_mem_any", STALLS_MEM_ANY),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_RECOVERY_MACHINE_CLEARS
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("machine_clears", MACHINE_CLEARS),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_RECOVERY_MEMORY_ORDERING
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("memory_ordering_clears", MEMORY_ORDERING_CLEARS),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_RECOVERY_CYCLES
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("recovery_cycles", RECOVERY_CYCLES),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_RECOVERY_CYCLES_ANY
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("recovery_cycles_any", RECOVERY_CYCLES_ANY),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_UOPS_RETIRED
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("uops_retired_slots", UOPS_RETIRED_SLOTS),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_UOPS_ISSUED
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("uops_issued_any", UOPS_ISSUED_ANY),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_UOPS_EXECUTED
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("uops_executed_thread", UOPS_EXECUTED_THREAD),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_FRONTEND_UOPS_UNDELIVERED
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("idq_uops_not_delivered", IDQ_UOPS_NOT_DELIVERED),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_FRONTEND_MITE_UOPS
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("mite_uops", IDQ_MITE_UOPS),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_FRONTEND_DSB_UOPS
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("dsb_uops", IDQ_DSB_UOPS),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_FRONTEND_MS_UOPS
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("microcode_uops", IDQ_MS_UOPS),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_BRANCH_CONDITIONAL
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("conditional_branches", BR_CONDITIONAL),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_BRANCH_CONDITIONAL_TAKEN
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("conditional_branches_taken", BR_CONDITIONAL_TAKEN),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_BRANCH_CONDITIONAL_NOT_TAKEN
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("conditional_branches_not_taken", BR_CONDITIONAL_NOT_TAKEN),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_BRANCH_MISPRED_CONDITIONAL
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("conditional_branch_mispredicts", BR_MISPRED_CONDITIONAL),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_RESOURCE_STALLS_SCOREBOARD
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("resource_stalls_scoreboard", RESOURCE_STALLS_SCOREBOARD),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_RESOURCE_STALLS_STORE_BUFFER
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("resource_stalls_store_buffer", RESOURCE_STALLS_STORE_BUFFER),
};
#elif SIO_COUNTER_SET == SIO_COUNTER_SET_EXECUTION_BOUND_LOADS
static const sio_event_desc sio_events[SIO_HPC_EVENT_COUNT] = {
    SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    SIO_EVENT_RAW("execution_bound_on_loads", EXECUTION_BOUND_LOADS),
};
#else
#error "invalid SIO_COUNTER_SET"
#endif
#endif

static const sio_event_desc sio_second_events[SIO_COUNTER_SET_COUNT + 1u] = {
    [SIO_COUNTER_SET_STRUCTURAL_INSTRUCTIONS] =
        SIO_EVENT_GENERIC("instructions", PERF_COUNT_HW_INSTRUCTIONS),
    [SIO_COUNTER_SET_STRUCTURAL_BRANCHES] =
        SIO_EVENT_GENERIC("branches", PERF_COUNT_HW_BRANCH_INSTRUCTIONS),
    [SIO_COUNTER_SET_STRUCTURAL_BRANCH_MISSES] =
        SIO_EVENT_GENERIC("branch_misses", PERF_COUNT_HW_BRANCH_MISSES),
    [SIO_COUNTER_SET_STRUCTURAL_LOADS] =
        {"retired_loads", SIO_PMU_TYPE, SIO_LOAD_CONFIG, 0, 0, 0, 1},
    [SIO_COUNTER_SET_STRUCTURAL_STORES] =
        {"retired_stores", SIO_PMU_TYPE, SIO_STORE_CONFIG, 0, 0, 0, 1},
    [SIO_COUNTER_SET_CACHE_L1D] = {
        "l1d_read_misses", PERF_TYPE_HW_CACHE,
        SIO_CACHE_CONFIG(PERF_COUNT_HW_CACHE_L1D, PERF_COUNT_HW_CACHE_OP_READ,
                          PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
    [SIO_COUNTER_SET_CACHE_L1I] = {
        "l1i_read_misses", PERF_TYPE_HW_CACHE,
        SIO_CACHE_CONFIG(PERF_COUNT_HW_CACHE_L1I, PERF_COUNT_HW_CACHE_OP_READ,
                          PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
    [SIO_COUNTER_SET_CACHE_LLC] = {
        "llc_read_misses", PERF_TYPE_HW_CACHE,
        SIO_CACHE_CONFIG(PERF_COUNT_HW_CACHE_LL, PERF_COUNT_HW_CACHE_OP_READ,
                          PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
    [SIO_COUNTER_SET_CACHE_DTLB] = {
        "dtlb_read_misses", PERF_TYPE_HW_CACHE,
        SIO_CACHE_CONFIG(PERF_COUNT_HW_CACHE_DTLB, PERF_COUNT_HW_CACHE_OP_READ,
                          PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
    [SIO_COUNTER_SET_CACHE_REFERENCES] =
        SIO_EVENT_GENERIC("cache_references", PERF_COUNT_HW_CACHE_REFERENCES),
    [SIO_COUNTER_SET_CACHE_MISSES] =
        SIO_EVENT_GENERIC("cache_misses", PERF_COUNT_HW_CACHE_MISSES),
    [SIO_COUNTER_SET_CACHE_L1D_REPLACEMENTS] =
        SIO_EVENT_RAW("l1d_replacements", L1D_REPLACEMENTS),
    [SIO_COUNTER_SET_CACHE_L2_REQUEST_MISSES] =
        SIO_EVENT_RAW("l2_request_misses", L2_REQUEST_MISSES),
    [SIO_COUNTER_SET_LOAD_L1_HIT] =
        SIO_EVENT_RAW("load_l1_hit", LOAD_L1_HIT),
    [SIO_COUNTER_SET_LOAD_L2_HIT] =
        SIO_EVENT_RAW("load_l2_hit", LOAD_L2_HIT),
    [SIO_COUNTER_SET_LOAD_L3_HIT] =
        SIO_EVENT_RAW("load_l3_hit", LOAD_L3_HIT),
    [SIO_COUNTER_SET_LOAD_L1_MISS] =
        SIO_EVENT_RAW("load_l1_miss", LOAD_L1_MISS),
    [SIO_COUNTER_SET_LOAD_L2_MISS] =
        SIO_EVENT_RAW("load_l2_miss", LOAD_L2_MISS),
    [SIO_COUNTER_SET_LOAD_L3_MISS] =
        SIO_EVENT_RAW("load_l3_miss", LOAD_L3_MISS),
    [SIO_COUNTER_SET_LONG_LATENCY_LOADS] =
        SIO_EVENT_RAW("long_latency_loads", LONG_LATENCY_LOADS),
    [SIO_COUNTER_SET_STALLS_FRONTEND] =
        SIO_EVENT_GENERIC("stalled_frontend_cycles",
                           PERF_COUNT_HW_STALLED_CYCLES_FRONTEND),
    [SIO_COUNTER_SET_STALLS_BACKEND] =
        SIO_EVENT_GENERIC("stalled_backend_cycles",
                           PERF_COUNT_HW_STALLED_CYCLES_BACKEND),
    [SIO_COUNTER_SET_STALLS_L1D_MISS] =
        SIO_EVENT_RAW("stalls_l1d_miss", STALLS_L1D_MISS),
    [SIO_COUNTER_SET_STALLS_MEM_ANY] =
        SIO_EVENT_RAW("stalls_mem_any", STALLS_MEM_ANY),
    [SIO_COUNTER_SET_RECOVERY_MACHINE_CLEARS] =
        SIO_EVENT_RAW("machine_clears", MACHINE_CLEARS),
    [SIO_COUNTER_SET_RECOVERY_MEMORY_ORDERING] =
        SIO_EVENT_RAW("memory_ordering_clears", MEMORY_ORDERING_CLEARS),
    [SIO_COUNTER_SET_RECOVERY_CYCLES] =
        SIO_EVENT_RAW("recovery_cycles", RECOVERY_CYCLES),
    [SIO_COUNTER_SET_RECOVERY_CYCLES_ANY] =
        SIO_EVENT_RAW("recovery_cycles_any", RECOVERY_CYCLES_ANY),
    [SIO_COUNTER_SET_UOPS_RETIRED] =
        SIO_EVENT_RAW("uops_retired_slots", UOPS_RETIRED_SLOTS),
    [SIO_COUNTER_SET_UOPS_ISSUED] =
        SIO_EVENT_RAW("uops_issued_any", UOPS_ISSUED_ANY),
    [SIO_COUNTER_SET_UOPS_EXECUTED] =
        SIO_EVENT_RAW("uops_executed_thread", UOPS_EXECUTED_THREAD),
    [SIO_COUNTER_SET_FRONTEND_UOPS_UNDELIVERED] =
        SIO_EVENT_RAW("idq_uops_not_delivered", IDQ_UOPS_NOT_DELIVERED),
    [SIO_COUNTER_SET_FRONTEND_MITE_UOPS] =
        SIO_EVENT_RAW("mite_uops", IDQ_MITE_UOPS),
    [SIO_COUNTER_SET_FRONTEND_DSB_UOPS] =
        SIO_EVENT_RAW("dsb_uops", IDQ_DSB_UOPS),
    [SIO_COUNTER_SET_FRONTEND_MS_UOPS] =
        SIO_EVENT_RAW("microcode_uops", IDQ_MS_UOPS),
    [SIO_COUNTER_SET_BRANCH_CONDITIONAL] =
        SIO_EVENT_RAW("conditional_branches", BR_CONDITIONAL),
    [SIO_COUNTER_SET_BRANCH_CONDITIONAL_TAKEN] =
        SIO_EVENT_RAW("conditional_branches_taken", BR_CONDITIONAL_TAKEN),
    [SIO_COUNTER_SET_BRANCH_CONDITIONAL_NOT_TAKEN] =
        SIO_EVENT_RAW("conditional_branches_not_taken", BR_CONDITIONAL_NOT_TAKEN),
    [SIO_COUNTER_SET_BRANCH_MISPRED_CONDITIONAL] =
        SIO_EVENT_RAW("conditional_branch_mispredicts", BR_MISPRED_CONDITIONAL),
    [SIO_COUNTER_SET_RESOURCE_STALLS_SCOREBOARD] =
        SIO_EVENT_RAW("resource_stalls_scoreboard", RESOURCE_STALLS_SCOREBOARD),
    [SIO_COUNTER_SET_RESOURCE_STALLS_STORE_BUFFER] =
        SIO_EVENT_RAW("resource_stalls_store_buffer", RESOURCE_STALLS_STORE_BUFFER),
    [SIO_COUNTER_SET_EXECUTION_BOUND_LOADS] =
        SIO_EVENT_RAW("execution_bound_on_loads", EXECUTION_BOUND_LOADS),
};

static sio_event_desc sio_events[SIO_HPC_EVENT_COUNT];

static int sio_fds[SIO_HPC_EVENT_COUNT] = {-1, -1};
static uint64_t sio_ids[SIO_HPC_EVENT_COUNT];
static uint32_t sio_requested_mask;
static uint32_t sio_available_mask;
static uint32_t sio_open_error_mask;
static int sio_hpc_ready;
static sio_hpc_snapshot sio_snapshot;

int sio_select_counter_set(unsigned int counter_set) {
    static const sio_event_desc cycles =
        SIO_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES);

    if (counter_set == 0u || counter_set > SIO_COUNTER_SET_COUNT) {
        return -EINVAL;
    }
    if (sio_hpc_ready) {
        return -EBUSY;
    }
    sio_events[0] = cycles;
    sio_events[1] = sio_second_events[counter_set];
    return 0;
}

static long sio_perf_event_open(struct perf_event_attr *attr,
                                pid_t pid,
                                int cpu,
                                int group_fd,
                                unsigned long flags) {
    return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static void sio_close_all(void) {
    unsigned int i;
    for (i = 0; i < SIO_HPC_EVENT_COUNT; ++i) {
        if (sio_fds[i] >= 0) {
            close(sio_fds[i]);
            sio_fds[i] = -1;
        }
        sio_ids[i] = 0;
    }
    sio_requested_mask = 0;
    sio_available_mask = 0;
    sio_open_error_mask = 0;
    sio_hpc_ready = 0;
}

int sio_hpc_init(void) {
    struct perf_event_attr attr;
    int leader = -1;
    unsigned int i;

    sio_close_all();
    memset(&sio_snapshot, 0, sizeof(sio_snapshot));

    for (i = 0; i < SIO_HPC_EVENT_COUNT; ++i) {
        int saved;

        if (!sio_events[i].available) {
            continue;
        }

        sio_requested_mask |= (uint32_t)(1u << i);
        memset(&attr, 0, sizeof(attr));
        attr.size = sizeof(attr);
        attr.type = sio_events[i].type;
        attr.config = sio_events[i].config;
        attr.config1 = sio_events[i].config1;
        attr.config2 = sio_events[i].config2;
        attr.precise_ip = sio_events[i].precise_ip;
        attr.disabled = 1;
        attr.exclude_kernel = 1;
        attr.exclude_hv = 1;
        attr.inherit = 0;
        attr.pinned = (i == 0u) ? 1u : 0u;
        attr.read_format =
            PERF_FORMAT_GROUP |
            PERF_FORMAT_ID |
            PERF_FORMAT_TOTAL_TIME_ENABLED |
            PERF_FORMAT_TOTAL_TIME_RUNNING;

        sio_fds[i] = (int)sio_perf_event_open(
            &attr, 0, -1, leader, PERF_FLAG_FD_CLOEXEC);

        if (sio_fds[i] < 0) {
            saved = errno;
            if (i == 0u) {
                sio_close_all();
                sio_snapshot.error_code = -saved;
                return -saved;
            }
            sio_open_error_mask |= (uint32_t)(1u << i);
            continue;
        }

        if (i == 0u) {
            leader = sio_fds[i];
        }

        if (ioctl(sio_fds[i], PERF_EVENT_IOC_ID, &sio_ids[i]) != 0) {
            saved = errno;
            close(sio_fds[i]);
            sio_fds[i] = -1;
            if (i == 0u) {
                sio_close_all();
                sio_snapshot.error_code = -saved;
                return -saved;
            }
            sio_open_error_mask |= (uint32_t)(1u << i);
            continue;
        }

        sio_available_mask |= (uint32_t)(1u << i);
    }

    if ((sio_available_mask & UINT32_C(0x1)) != UINT32_C(0x1)) {
        sio_close_all();
        sio_snapshot.error_code = -ENODEV;
        return -ENODEV;
    }

    sio_snapshot.requested_mask = sio_requested_mask;
    sio_snapshot.available_mask = sio_available_mask;
    sio_snapshot.open_error_mask = sio_open_error_mask;
    sio_hpc_ready = 1;
    return 0;
}

void sio_hpc_close(void) {
    sio_close_all();
}

const char *sio_event_name(unsigned int index) {
    return index < SIO_HPC_EVENT_COUNT ? sio_events[index].name : "unknown";
}

void sio_get_hpc_snapshot(sio_hpc_snapshot *out) {
    if (out != NULL) {
        *out = sio_snapshot;
    }
}

typedef struct {
    uint64_t value;
    uint64_t id;
} sio_read_value;

typedef struct {
    uint64_t nr;
    uint64_t time_enabled;
    uint64_t time_running;
    sio_read_value values[SIO_HPC_EVENT_COUNT];
} sio_group_read;

static inline void sio_barrier(void) {
    __asm__ volatile("" ::: "memory");
}

static inline void sio_hpc_begin(void) {
    sio_snapshot.error_code = 0;
    sio_barrier();
    if (ioctl(sio_fds[0], PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP) != 0) {
        sio_snapshot.error_code = -errno;
    }
    if (ioctl(sio_fds[0], PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP) != 0) {
        sio_snapshot.error_code = -errno;
    }
    sio_barrier();
}

static void sio_hpc_end(void) {
    sio_group_read data;
    ssize_t got;
    unsigned int i;
    unsigned int j;

    sio_barrier();
    if (ioctl(sio_fds[0], PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP) != 0) {
        sio_snapshot.error_code = -errno;
    }
    sio_barrier();

    memset(&data, 0, sizeof(data));
    got = read(sio_fds[0], &data, sizeof(data));

    sio_snapshot.sequence++;
    sio_snapshot.requested_mask = sio_requested_mask;
    sio_snapshot.available_mask = sio_available_mask;
    sio_snapshot.open_error_mask = sio_open_error_mask;
    sio_snapshot.valid_mask = 0;
    memset(sio_snapshot.values, 0, sizeof(sio_snapshot.values));

    if (got < (ssize_t)(3u * sizeof(uint64_t))) {
        sio_snapshot.error_code = got < 0 ? -errno : -EIO;
        return;
    }

    sio_snapshot.time_enabled = data.time_enabled;
    sio_snapshot.time_running = data.time_running;
    if (data.nr > SIO_HPC_EVENT_COUNT) {
        data.nr = SIO_HPC_EVENT_COUNT;
    }

    for (i = 0; i < data.nr; ++i) {
        for (j = 0; j < SIO_HPC_EVENT_COUNT; ++j) {
            if (data.values[i].id == sio_ids[j]) {
                sio_snapshot.values[j] = data.values[i].value;
                sio_snapshot.valid_mask |= (uint32_t)(1u << j);
                break;
            }
        }
    }
}



/*
 * Wang et al., "Secret in OnePiece"
 *
 * Semantic kernel for two local faults in a bitsliced masked decoder.
 * Source words are represented as two Boolean shares. The full decoder uses a
 * normal prefix, one fixed target operation, and a normal suffix.
 */
static inline unsigned int sio_masked_source_bit(
    const sio_job *job, unsigned int word, unsigned int bitpos) {
    uint16_t plain = (uint16_t)(job->share0[word] ^ job->share1[word]);
    return (unsigned int)((plain >> bitpos) & UINT16_C(1));
}

static inline uint16_t sio_insert_bit_normal_value(
    uint16_t dst, unsigned int bit, unsigned int bitpos) {
    uint16_t mask = (uint16_t)(UINT16_C(1) << bitpos);
    uint16_t placed = (uint16_t)((bit & 1u) << bitpos);
    dst = (uint16_t)(dst & (uint16_t)~mask);
    return (uint16_t)(dst | placed);
}

static void sio_copy_initial(sio_job *job) {
    unsigned int word;
    for (word = 0; word < SIO_NWORDS; ++word) {
        job->output[word] = job->initial[word];
    }
}

static void sio_decode_prefix(sio_job *job) {
    unsigned int index;
    for (index = 0; index < SIO_TARGET_LINEAR; ++index) {
        unsigned int word = index / SIO_WORD_BITS;
        unsigned int bitpos = index & (SIO_WORD_BITS - 1u);
        unsigned int bit = sio_masked_source_bit(job, word, bitpos);
        job->output[word] =
            sio_insert_bit_normal_value(job->output[word], bit, bitpos);
    }
}

static void sio_decode_suffix(sio_job *job) {
    unsigned int index;
    for (index = SIO_TARGET_LINEAR + 1u;
         index < SIO_TOTAL_INSERTIONS;
         ++index) {
        unsigned int word = index / SIO_WORD_BITS;
        unsigned int bitpos = index & (SIO_WORD_BITS - 1u);
        unsigned int bit = sio_masked_source_bit(job, word, bitpos);
        job->output[word] =
            sio_insert_bit_normal_value(job->output[word], bit, bitpos);
    }
}

/*
 * Baseline: load + clear + OR + destination assignment.
 * Assignment fault: load + clear + OR; only final writeback is omitted.
 * OR fault: load + clear + writeback; only target OR is omitted.
 */
SIO_NOINLINE
static void sio_target_insert_baseline(uint16_t *dst) {
    __asm__ volatile(
        "movzwl (%[dst]), %%eax\n\t"
        "andl $0xffffffdf, %%eax\n\t"
        "orl $0x20, %%eax\n\t"
        "movw %%ax, (%[dst])\n\t"
        :
        : [dst] "r"(dst)
        : "eax", "cc", "memory");
}

SIO_NOINLINE
static void sio_target_skip_assignment(uint16_t *dst) {
    __asm__ volatile(
        "movzwl (%[dst]), %%eax\n\t"
        "andl $0xffffffdf, %%eax\n\t"
        "orl $0x20, %%eax\n\t"
        :
        : [dst] "r"(dst)
        : "eax", "cc", "memory");
}

SIO_NOINLINE
static void sio_target_skip_or(uint16_t *dst) {
    __asm__ volatile(
        "movzwl (%[dst]), %%eax\n\t"
        "andl $0xffffffdf, %%eax\n\t"
        "movw %%ax, (%[dst])\n\t"
        :
        : [dst] "r"(dst)
        : "eax", "cc", "memory");
}

SIO_NOINLINE
void sio_decoder_baseline_target(sio_job *job) {
    sio_copy_initial(job);
    sio_decode_prefix(job);
    sio_target_insert_baseline(job->output + SIO_TARGET_WORD);
    sio_decode_suffix(job);
}

SIO_NOINLINE
void sio_decoder_skip_assignment_target(sio_job *job) {
    sio_copy_initial(job);
    sio_decode_prefix(job);
    sio_target_skip_assignment(job->output + SIO_TARGET_WORD);
    sio_decode_suffix(job);
}

SIO_NOINLINE
void sio_decoder_skip_or_target(sio_job *job) {
    sio_copy_initial(job);
    sio_decode_prefix(job);
    sio_target_skip_or(job->output + SIO_TARGET_WORD);
    sio_decode_suffix(job);
}

#define SIO_DEFINE_MEASURE_WRAPPER(name_, target_) \
    SIO_NOINLINE void name_(sio_job *job) { \
        if (!sio_hpc_ready) { \
            sio_snapshot.error_code = -ENODEV; \
            return; \
        } \
        sio_hpc_begin(); \
        target_(job); \
        sio_hpc_end(); \
    }

SIO_DEFINE_MEASURE_WRAPPER(
    sio_measure_decoder_baseline, sio_decoder_baseline_target)
SIO_DEFINE_MEASURE_WRAPPER(
    sio_measure_decoder_skip_assignment, sio_decoder_skip_assignment_target)
SIO_DEFINE_MEASURE_WRAPPER(
    sio_measure_decoder_skip_or, sio_decoder_skip_or_target)
