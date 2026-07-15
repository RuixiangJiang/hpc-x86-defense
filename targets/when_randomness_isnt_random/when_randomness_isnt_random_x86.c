#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "when_randomness_isnt_random_x86.h"
#include "microarch_events_generated.h"

#include <errno.h>
#include <linux/perf_event.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef WRIR_PMU_TYPE
#define WRIR_PMU_TYPE 4u
#endif

#ifndef WRIR_LOAD_CONFIG
#define WRIR_LOAD_CONFIG UINT64_C(0x81d0)
#endif

#ifndef WRIR_STORE_CONFIG
#define WRIR_STORE_CONFIG UINT64_C(0x82d0)
#endif



#if defined(__GNUC__) || defined(__clang__)
#define WRIR_NOINLINE __attribute__((noinline, noclone, used))
#else
#define WRIR_NOINLINE
#endif

typedef struct {
    const char *name;
    uint32_t type;
    uint64_t config;
    uint64_t config1;
    uint64_t config2;
    uint32_t precise_ip;
    uint32_t available;
} wrir_event_desc;

#define WRIR_EVENT_GENERIC(name_, config_) \
    {name_, PERF_TYPE_HARDWARE, config_, UINT64_C(0), UINT64_C(0), 0u, 1u}

#define WRIR_EVENT_RAW(name_, macro_) \
    { \
        name_, \
        WRIR_EVT_##macro_##_TYPE, \
        WRIR_EVT_##macro_##_CONFIG, \
        WRIR_EVT_##macro_##_CONFIG1, \
        WRIR_EVT_##macro_##_CONFIG2, \
        WRIR_EVT_##macro_##_PRECISE_IP, \
        WRIR_EVT_##macro_##_AVAILABLE \
    }

#define WRIR_CACHE_CONFIG(cache, op, result) \
    ((uint64_t)(cache) | ((uint64_t)(op) << 8) | ((uint64_t)(result) << 16))

/*
 * Retained only as a readable mapping from the previous compile-time build.
 * The active table below selects the same events at runtime so every
 * baseline, attack, and PMU pass uses exactly one ELF executable.
 */
#if 0
#if WRIR_COUNTER_SET == WRIR_COUNTER_SET_STRUCTURAL_INSTRUCTIONS
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_GENERIC("instructions", PERF_COUNT_HW_INSTRUCTIONS),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_STRUCTURAL_BRANCHES
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_GENERIC("branches", PERF_COUNT_HW_BRANCH_INSTRUCTIONS),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_STRUCTURAL_BRANCH_MISSES
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_GENERIC("branch_misses", PERF_COUNT_HW_BRANCH_MISSES),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_STRUCTURAL_LOADS
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"retired_loads", WRIR_PMU_TYPE, WRIR_LOAD_CONFIG, 0, 0, 0, 1},
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_STRUCTURAL_STORES
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"retired_stores", WRIR_PMU_TYPE, WRIR_STORE_CONFIG, 0, 0, 0, 1},
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_CACHE_L1D
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"l1d_read_misses", PERF_TYPE_HW_CACHE,
        WRIR_CACHE_CONFIG(PERF_COUNT_HW_CACHE_L1D, PERF_COUNT_HW_CACHE_OP_READ,
                         PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_CACHE_L1I
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"l1i_read_misses", PERF_TYPE_HW_CACHE,
        WRIR_CACHE_CONFIG(PERF_COUNT_HW_CACHE_L1I, PERF_COUNT_HW_CACHE_OP_READ,
                         PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_CACHE_LLC
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"llc_read_misses", PERF_TYPE_HW_CACHE,
        WRIR_CACHE_CONFIG(PERF_COUNT_HW_CACHE_LL, PERF_COUNT_HW_CACHE_OP_READ,
                         PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_CACHE_DTLB
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"dtlb_read_misses", PERF_TYPE_HW_CACHE,
        WRIR_CACHE_CONFIG(PERF_COUNT_HW_CACHE_DTLB, PERF_COUNT_HW_CACHE_OP_READ,
                         PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_CACHE_REFERENCES
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_GENERIC("cache_references", PERF_COUNT_HW_CACHE_REFERENCES),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_CACHE_MISSES
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_GENERIC("cache_misses", PERF_COUNT_HW_CACHE_MISSES),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_CACHE_L1D_REPLACEMENTS
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("l1d_replacements", L1D_REPLACEMENTS),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_CACHE_L2_REQUEST_MISSES
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("l2_request_misses", L2_REQUEST_MISSES),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_LOAD_L1_HIT
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("load_l1_hit", LOAD_L1_HIT),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_LOAD_L2_HIT
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("load_l2_hit", LOAD_L2_HIT),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_LOAD_L3_HIT
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("load_l3_hit", LOAD_L3_HIT),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_LOAD_L1_MISS
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("load_l1_miss", LOAD_L1_MISS),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_LOAD_L2_MISS
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("load_l2_miss", LOAD_L2_MISS),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_LOAD_L3_MISS
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("load_l3_miss", LOAD_L3_MISS),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_LONG_LATENCY_LOADS
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("long_latency_loads", LONG_LATENCY_LOADS),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_STALLS_FRONTEND
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_GENERIC("stalled_frontend_cycles", PERF_COUNT_HW_STALLED_CYCLES_FRONTEND),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_STALLS_BACKEND
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_GENERIC("stalled_backend_cycles", PERF_COUNT_HW_STALLED_CYCLES_BACKEND),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_STALLS_L1D_MISS
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("stalls_l1d_miss", STALLS_L1D_MISS),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_STALLS_MEM_ANY
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("stalls_mem_any", STALLS_MEM_ANY),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_RECOVERY_MACHINE_CLEARS
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("machine_clears", MACHINE_CLEARS),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_RECOVERY_MEMORY_ORDERING
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("memory_ordering_clears", MEMORY_ORDERING_CLEARS),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_RECOVERY_CYCLES
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("recovery_cycles", RECOVERY_CYCLES),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_RECOVERY_CYCLES_ANY
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("recovery_cycles_any", RECOVERY_CYCLES_ANY),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_UOPS_RETIRED
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("uops_retired_slots", UOPS_RETIRED_SLOTS),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_UOPS_ISSUED
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("uops_issued_any", UOPS_ISSUED_ANY),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_UOPS_EXECUTED
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("uops_executed_thread", UOPS_EXECUTED_THREAD),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_FRONTEND_UOPS_UNDELIVERED
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("idq_uops_not_delivered", IDQ_UOPS_NOT_DELIVERED),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_FRONTEND_MITE_UOPS
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("mite_uops", IDQ_MITE_UOPS),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_FRONTEND_DSB_UOPS
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("dsb_uops", IDQ_DSB_UOPS),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_FRONTEND_MS_UOPS
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("microcode_uops", IDQ_MS_UOPS),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_BRANCH_CONDITIONAL
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("conditional_branches", BR_CONDITIONAL),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_BRANCH_CONDITIONAL_TAKEN
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("conditional_branches_taken", BR_CONDITIONAL_TAKEN),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_BRANCH_CONDITIONAL_NOT_TAKEN
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("conditional_branches_not_taken", BR_CONDITIONAL_NOT_TAKEN),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_BRANCH_MISPRED_CONDITIONAL
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("conditional_branch_mispredicts", BR_MISPRED_CONDITIONAL),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_RESOURCE_STALLS_SCOREBOARD
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("resource_stalls_scoreboard", RESOURCE_STALLS_SCOREBOARD),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_RESOURCE_STALLS_STORE_BUFFER
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("resource_stalls_store_buffer", RESOURCE_STALLS_STORE_BUFFER),
};
#elif WRIR_COUNTER_SET == WRIR_COUNTER_SET_EXECUTION_BOUND_LOADS
static const wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT] = {
    WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    WRIR_EVENT_RAW("execution_bound_on_loads", EXECUTION_BOUND_LOADS),
};
#else
#error "invalid WRIR_COUNTER_SET"
#endif
#endif

static const wrir_event_desc wrir_second_events[WRIR_COUNTER_SET_COUNT + 1u] = {
    [WRIR_COUNTER_SET_STRUCTURAL_INSTRUCTIONS] =
        WRIR_EVENT_GENERIC("instructions", PERF_COUNT_HW_INSTRUCTIONS),
    [WRIR_COUNTER_SET_STRUCTURAL_BRANCHES] =
        WRIR_EVENT_GENERIC("branches", PERF_COUNT_HW_BRANCH_INSTRUCTIONS),
    [WRIR_COUNTER_SET_STRUCTURAL_BRANCH_MISSES] =
        WRIR_EVENT_GENERIC("branch_misses", PERF_COUNT_HW_BRANCH_MISSES),
    [WRIR_COUNTER_SET_STRUCTURAL_LOADS] =
        {"retired_loads", WRIR_PMU_TYPE, WRIR_LOAD_CONFIG, 0, 0, 0, 1},
    [WRIR_COUNTER_SET_STRUCTURAL_STORES] =
        {"retired_stores", WRIR_PMU_TYPE, WRIR_STORE_CONFIG, 0, 0, 0, 1},
    [WRIR_COUNTER_SET_CACHE_L1D] = {
        "l1d_read_misses", PERF_TYPE_HW_CACHE,
        WRIR_CACHE_CONFIG(PERF_COUNT_HW_CACHE_L1D, PERF_COUNT_HW_CACHE_OP_READ,
                          PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
    [WRIR_COUNTER_SET_CACHE_L1I] = {
        "l1i_read_misses", PERF_TYPE_HW_CACHE,
        WRIR_CACHE_CONFIG(PERF_COUNT_HW_CACHE_L1I, PERF_COUNT_HW_CACHE_OP_READ,
                          PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
    [WRIR_COUNTER_SET_CACHE_LLC] = {
        "llc_read_misses", PERF_TYPE_HW_CACHE,
        WRIR_CACHE_CONFIG(PERF_COUNT_HW_CACHE_LL, PERF_COUNT_HW_CACHE_OP_READ,
                          PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
    [WRIR_COUNTER_SET_CACHE_DTLB] = {
        "dtlb_read_misses", PERF_TYPE_HW_CACHE,
        WRIR_CACHE_CONFIG(PERF_COUNT_HW_CACHE_DTLB, PERF_COUNT_HW_CACHE_OP_READ,
                          PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
    [WRIR_COUNTER_SET_CACHE_REFERENCES] =
        WRIR_EVENT_GENERIC("cache_references", PERF_COUNT_HW_CACHE_REFERENCES),
    [WRIR_COUNTER_SET_CACHE_MISSES] =
        WRIR_EVENT_GENERIC("cache_misses", PERF_COUNT_HW_CACHE_MISSES),
    [WRIR_COUNTER_SET_CACHE_L1D_REPLACEMENTS] =
        WRIR_EVENT_RAW("l1d_replacements", L1D_REPLACEMENTS),
    [WRIR_COUNTER_SET_CACHE_L2_REQUEST_MISSES] =
        WRIR_EVENT_RAW("l2_request_misses", L2_REQUEST_MISSES),
    [WRIR_COUNTER_SET_LOAD_L1_HIT] =
        WRIR_EVENT_RAW("load_l1_hit", LOAD_L1_HIT),
    [WRIR_COUNTER_SET_LOAD_L2_HIT] =
        WRIR_EVENT_RAW("load_l2_hit", LOAD_L2_HIT),
    [WRIR_COUNTER_SET_LOAD_L3_HIT] =
        WRIR_EVENT_RAW("load_l3_hit", LOAD_L3_HIT),
    [WRIR_COUNTER_SET_LOAD_L1_MISS] =
        WRIR_EVENT_RAW("load_l1_miss", LOAD_L1_MISS),
    [WRIR_COUNTER_SET_LOAD_L2_MISS] =
        WRIR_EVENT_RAW("load_l2_miss", LOAD_L2_MISS),
    [WRIR_COUNTER_SET_LOAD_L3_MISS] =
        WRIR_EVENT_RAW("load_l3_miss", LOAD_L3_MISS),
    [WRIR_COUNTER_SET_LONG_LATENCY_LOADS] =
        WRIR_EVENT_RAW("long_latency_loads", LONG_LATENCY_LOADS),
    [WRIR_COUNTER_SET_STALLS_FRONTEND] =
        WRIR_EVENT_GENERIC("stalled_frontend_cycles",
                           PERF_COUNT_HW_STALLED_CYCLES_FRONTEND),
    [WRIR_COUNTER_SET_STALLS_BACKEND] =
        WRIR_EVENT_GENERIC("stalled_backend_cycles",
                           PERF_COUNT_HW_STALLED_CYCLES_BACKEND),
    [WRIR_COUNTER_SET_STALLS_L1D_MISS] =
        WRIR_EVENT_RAW("stalls_l1d_miss", STALLS_L1D_MISS),
    [WRIR_COUNTER_SET_STALLS_MEM_ANY] =
        WRIR_EVENT_RAW("stalls_mem_any", STALLS_MEM_ANY),
    [WRIR_COUNTER_SET_RECOVERY_MACHINE_CLEARS] =
        WRIR_EVENT_RAW("machine_clears", MACHINE_CLEARS),
    [WRIR_COUNTER_SET_RECOVERY_MEMORY_ORDERING] =
        WRIR_EVENT_RAW("memory_ordering_clears", MEMORY_ORDERING_CLEARS),
    [WRIR_COUNTER_SET_RECOVERY_CYCLES] =
        WRIR_EVENT_RAW("recovery_cycles", RECOVERY_CYCLES),
    [WRIR_COUNTER_SET_RECOVERY_CYCLES_ANY] =
        WRIR_EVENT_RAW("recovery_cycles_any", RECOVERY_CYCLES_ANY),
    [WRIR_COUNTER_SET_UOPS_RETIRED] =
        WRIR_EVENT_RAW("uops_retired_slots", UOPS_RETIRED_SLOTS),
    [WRIR_COUNTER_SET_UOPS_ISSUED] =
        WRIR_EVENT_RAW("uops_issued_any", UOPS_ISSUED_ANY),
    [WRIR_COUNTER_SET_UOPS_EXECUTED] =
        WRIR_EVENT_RAW("uops_executed_thread", UOPS_EXECUTED_THREAD),
    [WRIR_COUNTER_SET_FRONTEND_UOPS_UNDELIVERED] =
        WRIR_EVENT_RAW("idq_uops_not_delivered", IDQ_UOPS_NOT_DELIVERED),
    [WRIR_COUNTER_SET_FRONTEND_MITE_UOPS] =
        WRIR_EVENT_RAW("mite_uops", IDQ_MITE_UOPS),
    [WRIR_COUNTER_SET_FRONTEND_DSB_UOPS] =
        WRIR_EVENT_RAW("dsb_uops", IDQ_DSB_UOPS),
    [WRIR_COUNTER_SET_FRONTEND_MS_UOPS] =
        WRIR_EVENT_RAW("microcode_uops", IDQ_MS_UOPS),
    [WRIR_COUNTER_SET_BRANCH_CONDITIONAL] =
        WRIR_EVENT_RAW("conditional_branches", BR_CONDITIONAL),
    [WRIR_COUNTER_SET_BRANCH_CONDITIONAL_TAKEN] =
        WRIR_EVENT_RAW("conditional_branches_taken", BR_CONDITIONAL_TAKEN),
    [WRIR_COUNTER_SET_BRANCH_CONDITIONAL_NOT_TAKEN] =
        WRIR_EVENT_RAW("conditional_branches_not_taken", BR_CONDITIONAL_NOT_TAKEN),
    [WRIR_COUNTER_SET_BRANCH_MISPRED_CONDITIONAL] =
        WRIR_EVENT_RAW("conditional_branch_mispredicts", BR_MISPRED_CONDITIONAL),
    [WRIR_COUNTER_SET_RESOURCE_STALLS_SCOREBOARD] =
        WRIR_EVENT_RAW("resource_stalls_scoreboard", RESOURCE_STALLS_SCOREBOARD),
    [WRIR_COUNTER_SET_RESOURCE_STALLS_STORE_BUFFER] =
        WRIR_EVENT_RAW("resource_stalls_store_buffer", RESOURCE_STALLS_STORE_BUFFER),
    [WRIR_COUNTER_SET_EXECUTION_BOUND_LOADS] =
        WRIR_EVENT_RAW("execution_bound_on_loads", EXECUTION_BOUND_LOADS),
};

static wrir_event_desc wrir_events[WRIR_HPC_EVENT_COUNT];

static int wrir_fds[WRIR_HPC_EVENT_COUNT] = {-1, -1};
static uint64_t wrir_ids[WRIR_HPC_EVENT_COUNT];
static uint32_t wrir_requested_mask;
static uint32_t wrir_available_mask;
static uint32_t wrir_open_error_mask;
static int wrir_hpc_ready;
static wrir_hpc_snapshot wrir_snapshot;

int wrir_select_counter_set(unsigned int counter_set) {
    static const wrir_event_desc cycles =
        WRIR_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES);

    if (counter_set == 0u || counter_set > WRIR_COUNTER_SET_COUNT) {
        return -EINVAL;
    }
    if (wrir_hpc_ready) {
        return -EBUSY;
    }
    wrir_events[0] = cycles;
    wrir_events[1] = wrir_second_events[counter_set];
    return 0;
}

static long wrir_perf_event_open(struct perf_event_attr *attr,
                                pid_t pid,
                                int cpu,
                                int group_fd,
                                unsigned long flags) {
    return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static void wrir_close_all(void) {
    unsigned int i;
    for (i = 0; i < WRIR_HPC_EVENT_COUNT; ++i) {
        if (wrir_fds[i] >= 0) {
            close(wrir_fds[i]);
            wrir_fds[i] = -1;
        }
        wrir_ids[i] = 0;
    }
    wrir_requested_mask = 0;
    wrir_available_mask = 0;
    wrir_open_error_mask = 0;
    wrir_hpc_ready = 0;
}

int wrir_hpc_init(void) {
    struct perf_event_attr attr;
    int leader = -1;
    unsigned int i;

    wrir_close_all();
    memset(&wrir_snapshot, 0, sizeof(wrir_snapshot));

    for (i = 0; i < WRIR_HPC_EVENT_COUNT; ++i) {
        int saved;

        if (!wrir_events[i].available) {
            continue;
        }

        wrir_requested_mask |= (uint32_t)(1u << i);
        memset(&attr, 0, sizeof(attr));
        attr.size = sizeof(attr);
        attr.type = wrir_events[i].type;
        attr.config = wrir_events[i].config;
        attr.config1 = wrir_events[i].config1;
        attr.config2 = wrir_events[i].config2;
        attr.precise_ip = wrir_events[i].precise_ip;
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

        wrir_fds[i] = (int)wrir_perf_event_open(
            &attr, 0, -1, leader, PERF_FLAG_FD_CLOEXEC);

        if (wrir_fds[i] < 0) {
            saved = errno;
            if (i == 0u) {
                wrir_close_all();
                wrir_snapshot.error_code = -saved;
                return -saved;
            }
            wrir_open_error_mask |= (uint32_t)(1u << i);
            continue;
        }

        if (i == 0u) {
            leader = wrir_fds[i];
        }

        if (ioctl(wrir_fds[i], PERF_EVENT_IOC_ID, &wrir_ids[i]) != 0) {
            saved = errno;
            close(wrir_fds[i]);
            wrir_fds[i] = -1;
            if (i == 0u) {
                wrir_close_all();
                wrir_snapshot.error_code = -saved;
                return -saved;
            }
            wrir_open_error_mask |= (uint32_t)(1u << i);
            continue;
        }

        wrir_available_mask |= (uint32_t)(1u << i);
    }

    if ((wrir_available_mask & UINT32_C(0x1)) != UINT32_C(0x1)) {
        wrir_close_all();
        wrir_snapshot.error_code = -ENODEV;
        return -ENODEV;
    }

    wrir_snapshot.requested_mask = wrir_requested_mask;
    wrir_snapshot.available_mask = wrir_available_mask;
    wrir_snapshot.open_error_mask = wrir_open_error_mask;
    wrir_hpc_ready = 1;
    return 0;
}

void wrir_hpc_close(void) {
    wrir_close_all();
}

const char *wrir_event_name(unsigned int index) {
    return index < WRIR_HPC_EVENT_COUNT ? wrir_events[index].name : "unknown";
}

void wrir_get_hpc_snapshot(wrir_hpc_snapshot *out) {
    if (out != NULL) {
        *out = wrir_snapshot;
    }
}

typedef struct {
    uint64_t value;
    uint64_t id;
} wrir_read_value;

typedef struct {
    uint64_t nr;
    uint64_t time_enabled;
    uint64_t time_running;
    wrir_read_value values[WRIR_HPC_EVENT_COUNT];
} wrir_group_read;

static inline void wrir_barrier(void) {
    __asm__ volatile("" ::: "memory");
}

static inline void wrir_hpc_begin(void) {
    wrir_snapshot.error_code = 0;
    wrir_barrier();
    if (ioctl(wrir_fds[0], PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP) != 0) {
        wrir_snapshot.error_code = -errno;
    }
    if (ioctl(wrir_fds[0], PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP) != 0) {
        wrir_snapshot.error_code = -errno;
    }
    wrir_barrier();
}

static void wrir_hpc_end(void) {
    wrir_group_read data;
    ssize_t got;
    unsigned int i;
    unsigned int j;

    wrir_barrier();
    if (ioctl(wrir_fds[0], PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP) != 0) {
        wrir_snapshot.error_code = -errno;
    }
    wrir_barrier();

    memset(&data, 0, sizeof(data));
    got = read(wrir_fds[0], &data, sizeof(data));

    wrir_snapshot.sequence++;
    wrir_snapshot.requested_mask = wrir_requested_mask;
    wrir_snapshot.available_mask = wrir_available_mask;
    wrir_snapshot.open_error_mask = wrir_open_error_mask;
    wrir_snapshot.valid_mask = 0;
    memset(wrir_snapshot.values, 0, sizeof(wrir_snapshot.values));

    if (got < (ssize_t)(3u * sizeof(uint64_t))) {
        wrir_snapshot.error_code = got < 0 ? -errno : -EIO;
        return;
    }

    wrir_snapshot.time_enabled = data.time_enabled;
    wrir_snapshot.time_running = data.time_running;
    if (data.nr > WRIR_HPC_EVENT_COUNT) {
        data.nr = WRIR_HPC_EVENT_COUNT;
    }

    for (i = 0; i < data.nr; ++i) {
        for (j = 0; j < WRIR_HPC_EVENT_COUNT; ++j) {
            if (data.values[i].id == wrir_ids[j]) {
                wrir_snapshot.values[j] = data.values[i].value;
                wrir_snapshot.valid_mask |= (uint32_t)(1u << j);
                break;
            }
        }
    }
}


static const uint64_t wrir_round_constants[24] = {
    UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
    UINT64_C(0x800000000000808a), UINT64_C(0x8000000080008000),
    UINT64_C(0x000000000000808b), UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
    UINT64_C(0x000000000000008a), UINT64_C(0x0000000000000088),
    UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000a),
    UINT64_C(0x000000008000808b), UINT64_C(0x800000000000008b),
    UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
    UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
    UINT64_C(0x000000000000800a), UINT64_C(0x800000008000000a),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
    UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008)
};

static const unsigned int wrir_rotation[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const unsigned int wrir_pilane[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

static inline uint64_t wrir_rol64(uint64_t x, unsigned int shift) {
    return (x << shift) | (x >> (64u - shift));
}

static void wrir_keccakf1600(uint64_t state[25]) {
    uint64_t bc[5];
    uint64_t t;
    unsigned int round;
    unsigned int i;
    unsigned int j;

    for (round = 0; round < 24u; ++round) {
        for (i = 0; i < 5u; ++i) {
            bc[i] = state[i] ^ state[i + 5u] ^ state[i + 10u] ^
                    state[i + 15u] ^ state[i + 20u];
        }
        for (i = 0; i < 5u; ++i) {
            t = bc[(i + 4u) % 5u] ^ wrir_rol64(bc[(i + 1u) % 5u], 1u);
            for (j = 0; j < 25u; j += 5u) {
                state[j + i] ^= t;
            }
        }
        t = state[1];
        for (i = 0; i < 24u; ++i) {
            j = wrir_pilane[i];
            bc[0] = state[j];
            state[j] = wrir_rol64(t, wrir_rotation[i]);
            t = bc[0];
        }
        for (j = 0; j < 25u; j += 5u) {
            for (i = 0; i < 5u; ++i) {
                bc[i] = state[j + i];
            }
            for (i = 0; i < 5u; ++i) {
                state[j + i] = bc[i] ^ ((~bc[(i + 1u) % 5u]) & bc[(i + 2u) % 5u]);
            }
        }
        state[0] ^= wrir_round_constants[round];
    }
}

#define WRIR_SHAKE256_RATE 136u

typedef struct {
    uint64_t state[25];
    unsigned int position;
} wrir_shake256_state;

static void wrir_xor_byte(uint64_t state[25], unsigned int index, uint8_t value) {
    state[index >> 3] ^= (uint64_t)value << (8u * (index & 7u));
}

static uint8_t wrir_get_byte(const uint64_t state[25], unsigned int index) {
    return (uint8_t)(state[index >> 3] >> (8u * (index & 7u)));
}

static void wrir_stream256_init(wrir_shake256_state *ctx,
                                const uint8_t seed[WRIR_CRHBYTES],
                                uint16_t nonce) {
    unsigned int i;
    memset(ctx, 0, sizeof(*ctx));
    for (i = 0; i < WRIR_CRHBYTES; ++i) {
        wrir_xor_byte(ctx->state, i, seed[i]);
    }
    wrir_xor_byte(ctx->state, WRIR_CRHBYTES, (uint8_t)nonce);
    wrir_xor_byte(ctx->state, WRIR_CRHBYTES + 1u, (uint8_t)(nonce >> 8));
    wrir_xor_byte(ctx->state, WRIR_CRHBYTES + 2u, UINT8_C(0x1f));
    wrir_xor_byte(ctx->state, WRIR_SHAKE256_RATE - 1u, UINT8_C(0x80));
    ctx->position = WRIR_SHAKE256_RATE;
}

static void wrir_stream256_squeezeblock(uint8_t out[WRIR_SHAKE256_RATE],
                                        wrir_shake256_state *ctx) {
    unsigned int i;
    wrir_keccakf1600(ctx->state);
    for (i = 0; i < WRIR_SHAKE256_RATE; ++i) {
        out[i] = wrir_get_byte(ctx->state, i);
    }
    ctx->position = 0u;
}

static unsigned int wrir_rej_eta(int32_t *out, unsigned int length,
                                 const uint8_t *buf, unsigned int buflen) {
    unsigned int ctr = 0u;
    unsigned int pos = 0u;
    while (ctr < length && pos < buflen) {
        uint32_t t0 = buf[pos] & UINT8_C(0x0f);
        uint32_t t1 = buf[pos++] >> 4;
        if (t0 < 15u) {
            t0 = t0 - ((205u * t0) >> 10) * 5u;
            out[ctr++] = 2 - (int32_t)t0;
        }
        if (t1 < 15u && ctr < length) {
            t1 = t1 - ((205u * t1) >> 10) * 5u;
            out[ctr++] = 2 - (int32_t)t1;
        }
    }
    return ctr;
}

/*
 * This is the unmodified ML-DSA/Dilithium-style data path being measured:
 * SHAKE256(seed || nonce), followed by ETA=2 rejection sampling.
 * All three fault models change only seed/nonce arguments before entry.
 */
WRIR_NOINLINE
void wrir_sampler_target(wrir_poly *out,
                         const uint8_t seed[WRIR_CRHBYTES],
                         uint16_t nonce) {
    uint8_t buf[WRIR_SHAKE256_RATE];
    wrir_shake256_state state;
    unsigned int ctr;

    wrir_stream256_init(&state, seed, nonce);
    wrir_stream256_squeezeblock(buf, &state);
    ctr = wrir_rej_eta(out->coeffs, WRIR_N, buf, WRIR_SHAKE256_RATE);
    while (ctr < WRIR_N) {
        wrir_stream256_squeezeblock(buf, &state);
        ctr += wrir_rej_eta(out->coeffs + ctr, WRIR_N - ctr,
                            buf, WRIR_SHAKE256_RATE);
    }
}

void wrir_reference_sampler(wrir_poly *out,
                            const uint8_t seed[WRIR_CRHBYTES],
                            uint16_t nonce) {
    wrir_sampler_target(out, seed, nonce);
}

WRIR_NOINLINE
void wrir_measure_target(wrir_poly *out,
                         const uint8_t seed[WRIR_CRHBYTES],
                         uint16_t nonce) {
    if (!wrir_hpc_ready) {
        wrir_snapshot.error_code = -ENODEV;
        return;
    }
    wrir_hpc_begin();
    wrir_sampler_target(out, seed, nonce);
    wrir_hpc_end();
}
