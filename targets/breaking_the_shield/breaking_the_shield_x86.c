#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "breaking_the_shield_x86.h"
#include "microarch_events_generated.h"

#include <errno.h>
#include <linux/perf_event.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef BTS_PMU_TYPE
#define BTS_PMU_TYPE 4u
#endif

#ifndef BTS_LOAD_CONFIG
#define BTS_LOAD_CONFIG UINT64_C(0x81d0)
#endif

#ifndef BTS_STORE_CONFIG
#define BTS_STORE_CONFIG UINT64_C(0x82d0)
#endif



#if defined(__GNUC__) || defined(__clang__)
#define BTS_NOINLINE __attribute__((noinline, noclone, used))
#else
#define BTS_NOINLINE
#endif

typedef struct {
    const char *name;
    uint32_t type;
    uint64_t config;
    uint64_t config1;
    uint64_t config2;
    uint32_t precise_ip;
    uint32_t available;
} bts_event_desc;

#define BTS_EVENT_GENERIC(name_, config_) \
    {name_, PERF_TYPE_HARDWARE, config_, UINT64_C(0), UINT64_C(0), 0u, 1u}

#define BTS_EVENT_RAW(name_, macro_) \
    { \
        name_, \
        BTS_EVT_##macro_##_TYPE, \
        BTS_EVT_##macro_##_CONFIG, \
        BTS_EVT_##macro_##_CONFIG1, \
        BTS_EVT_##macro_##_CONFIG2, \
        BTS_EVT_##macro_##_PRECISE_IP, \
        BTS_EVT_##macro_##_AVAILABLE \
    }

#define BTS_CACHE_CONFIG(cache, op, result) \
    ((uint64_t)(cache) | ((uint64_t)(op) << 8) | ((uint64_t)(result) << 16))

/*
 * Retained only as a readable mapping from the previous compile-time build.
 * The active table below selects the same events at runtime so every
 * baseline, attack, and PMU pass uses exactly one ELF executable.
 */
#if 0
#if BTS_COUNTER_SET == BTS_COUNTER_SET_STRUCTURAL_INSTRUCTIONS
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_GENERIC("instructions", PERF_COUNT_HW_INSTRUCTIONS),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_STRUCTURAL_BRANCHES
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_GENERIC("branches", PERF_COUNT_HW_BRANCH_INSTRUCTIONS),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_STRUCTURAL_BRANCH_MISSES
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_GENERIC("branch_misses", PERF_COUNT_HW_BRANCH_MISSES),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_STRUCTURAL_LOADS
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"retired_loads", BTS_PMU_TYPE, BTS_LOAD_CONFIG, 0, 0, 0, 1},
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_STRUCTURAL_STORES
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"retired_stores", BTS_PMU_TYPE, BTS_STORE_CONFIG, 0, 0, 0, 1},
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_CACHE_L1D
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"l1d_read_misses", PERF_TYPE_HW_CACHE,
        BTS_CACHE_CONFIG(PERF_COUNT_HW_CACHE_L1D, PERF_COUNT_HW_CACHE_OP_READ,
                         PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_CACHE_L1I
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"l1i_read_misses", PERF_TYPE_HW_CACHE,
        BTS_CACHE_CONFIG(PERF_COUNT_HW_CACHE_L1I, PERF_COUNT_HW_CACHE_OP_READ,
                         PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_CACHE_LLC
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"llc_read_misses", PERF_TYPE_HW_CACHE,
        BTS_CACHE_CONFIG(PERF_COUNT_HW_CACHE_LL, PERF_COUNT_HW_CACHE_OP_READ,
                         PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_CACHE_DTLB
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"dtlb_read_misses", PERF_TYPE_HW_CACHE,
        BTS_CACHE_CONFIG(PERF_COUNT_HW_CACHE_DTLB, PERF_COUNT_HW_CACHE_OP_READ,
                         PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_CACHE_REFERENCES
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_GENERIC("cache_references", PERF_COUNT_HW_CACHE_REFERENCES),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_CACHE_MISSES
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_GENERIC("cache_misses", PERF_COUNT_HW_CACHE_MISSES),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_CACHE_L1D_REPLACEMENTS
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("l1d_replacements", L1D_REPLACEMENTS),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_CACHE_L2_REQUEST_MISSES
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("l2_request_misses", L2_REQUEST_MISSES),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_LOAD_L1_HIT
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("load_l1_hit", LOAD_L1_HIT),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_LOAD_L2_HIT
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("load_l2_hit", LOAD_L2_HIT),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_LOAD_L3_HIT
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("load_l3_hit", LOAD_L3_HIT),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_LOAD_L1_MISS
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("load_l1_miss", LOAD_L1_MISS),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_LOAD_L2_MISS
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("load_l2_miss", LOAD_L2_MISS),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_LOAD_L3_MISS
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("load_l3_miss", LOAD_L3_MISS),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_LONG_LATENCY_LOADS
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("long_latency_loads", LONG_LATENCY_LOADS),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_STALLS_FRONTEND
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_GENERIC("stalled_frontend_cycles", PERF_COUNT_HW_STALLED_CYCLES_FRONTEND),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_STALLS_BACKEND
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_GENERIC("stalled_backend_cycles", PERF_COUNT_HW_STALLED_CYCLES_BACKEND),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_STALLS_L1D_MISS
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("stalls_l1d_miss", STALLS_L1D_MISS),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_STALLS_MEM_ANY
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("stalls_mem_any", STALLS_MEM_ANY),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_RECOVERY_MACHINE_CLEARS
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("machine_clears", MACHINE_CLEARS),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_RECOVERY_MEMORY_ORDERING
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("memory_ordering_clears", MEMORY_ORDERING_CLEARS),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_RECOVERY_CYCLES
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("recovery_cycles", RECOVERY_CYCLES),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_RECOVERY_CYCLES_ANY
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("recovery_cycles_any", RECOVERY_CYCLES_ANY),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_UOPS_RETIRED
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("uops_retired_slots", UOPS_RETIRED_SLOTS),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_UOPS_ISSUED
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("uops_issued_any", UOPS_ISSUED_ANY),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_UOPS_EXECUTED
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("uops_executed_thread", UOPS_EXECUTED_THREAD),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_FRONTEND_UOPS_UNDELIVERED
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("idq_uops_not_delivered", IDQ_UOPS_NOT_DELIVERED),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_FRONTEND_MITE_UOPS
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("mite_uops", IDQ_MITE_UOPS),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_FRONTEND_DSB_UOPS
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("dsb_uops", IDQ_DSB_UOPS),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_FRONTEND_MS_UOPS
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("microcode_uops", IDQ_MS_UOPS),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_BRANCH_CONDITIONAL
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("conditional_branches", BR_CONDITIONAL),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_BRANCH_CONDITIONAL_TAKEN
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("conditional_branches_taken", BR_CONDITIONAL_TAKEN),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_BRANCH_CONDITIONAL_NOT_TAKEN
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("conditional_branches_not_taken", BR_CONDITIONAL_NOT_TAKEN),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_BRANCH_MISPRED_CONDITIONAL
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("conditional_branch_mispredicts", BR_MISPRED_CONDITIONAL),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_RESOURCE_STALLS_SCOREBOARD
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("resource_stalls_scoreboard", RESOURCE_STALLS_SCOREBOARD),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_RESOURCE_STALLS_STORE_BUFFER
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("resource_stalls_store_buffer", RESOURCE_STALLS_STORE_BUFFER),
};
#elif BTS_COUNTER_SET == BTS_COUNTER_SET_EXECUTION_BOUND_LOADS
static const bts_event_desc bts_events[BTS_HPC_EVENT_COUNT] = {
    BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    BTS_EVENT_RAW("execution_bound_on_loads", EXECUTION_BOUND_LOADS),
};
#else
#error "invalid BTS_COUNTER_SET"
#endif
#endif

static const bts_event_desc bts_second_events[BTS_COUNTER_SET_COUNT + 1u] = {
    [BTS_COUNTER_SET_STRUCTURAL_INSTRUCTIONS] =
        BTS_EVENT_GENERIC("instructions", PERF_COUNT_HW_INSTRUCTIONS),
    [BTS_COUNTER_SET_STRUCTURAL_BRANCHES] =
        BTS_EVENT_GENERIC("branches", PERF_COUNT_HW_BRANCH_INSTRUCTIONS),
    [BTS_COUNTER_SET_STRUCTURAL_BRANCH_MISSES] =
        BTS_EVENT_GENERIC("branch_misses", PERF_COUNT_HW_BRANCH_MISSES),
    [BTS_COUNTER_SET_STRUCTURAL_LOADS] =
        {"retired_loads", BTS_PMU_TYPE, BTS_LOAD_CONFIG, 0, 0, 0, 1},
    [BTS_COUNTER_SET_STRUCTURAL_STORES] =
        {"retired_stores", BTS_PMU_TYPE, BTS_STORE_CONFIG, 0, 0, 0, 1},
    [BTS_COUNTER_SET_CACHE_L1D] = {
        "l1d_read_misses", PERF_TYPE_HW_CACHE,
        BTS_CACHE_CONFIG(PERF_COUNT_HW_CACHE_L1D, PERF_COUNT_HW_CACHE_OP_READ,
                          PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
    [BTS_COUNTER_SET_CACHE_L1I] = {
        "l1i_read_misses", PERF_TYPE_HW_CACHE,
        BTS_CACHE_CONFIG(PERF_COUNT_HW_CACHE_L1I, PERF_COUNT_HW_CACHE_OP_READ,
                          PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
    [BTS_COUNTER_SET_CACHE_LLC] = {
        "llc_read_misses", PERF_TYPE_HW_CACHE,
        BTS_CACHE_CONFIG(PERF_COUNT_HW_CACHE_LL, PERF_COUNT_HW_CACHE_OP_READ,
                          PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
    [BTS_COUNTER_SET_CACHE_DTLB] = {
        "dtlb_read_misses", PERF_TYPE_HW_CACHE,
        BTS_CACHE_CONFIG(PERF_COUNT_HW_CACHE_DTLB, PERF_COUNT_HW_CACHE_OP_READ,
                          PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
    [BTS_COUNTER_SET_CACHE_REFERENCES] =
        BTS_EVENT_GENERIC("cache_references", PERF_COUNT_HW_CACHE_REFERENCES),
    [BTS_COUNTER_SET_CACHE_MISSES] =
        BTS_EVENT_GENERIC("cache_misses", PERF_COUNT_HW_CACHE_MISSES),
    [BTS_COUNTER_SET_CACHE_L1D_REPLACEMENTS] =
        BTS_EVENT_RAW("l1d_replacements", L1D_REPLACEMENTS),
    [BTS_COUNTER_SET_CACHE_L2_REQUEST_MISSES] =
        BTS_EVENT_RAW("l2_request_misses", L2_REQUEST_MISSES),
    [BTS_COUNTER_SET_LOAD_L1_HIT] =
        BTS_EVENT_RAW("load_l1_hit", LOAD_L1_HIT),
    [BTS_COUNTER_SET_LOAD_L2_HIT] =
        BTS_EVENT_RAW("load_l2_hit", LOAD_L2_HIT),
    [BTS_COUNTER_SET_LOAD_L3_HIT] =
        BTS_EVENT_RAW("load_l3_hit", LOAD_L3_HIT),
    [BTS_COUNTER_SET_LOAD_L1_MISS] =
        BTS_EVENT_RAW("load_l1_miss", LOAD_L1_MISS),
    [BTS_COUNTER_SET_LOAD_L2_MISS] =
        BTS_EVENT_RAW("load_l2_miss", LOAD_L2_MISS),
    [BTS_COUNTER_SET_LOAD_L3_MISS] =
        BTS_EVENT_RAW("load_l3_miss", LOAD_L3_MISS),
    [BTS_COUNTER_SET_LONG_LATENCY_LOADS] =
        BTS_EVENT_RAW("long_latency_loads", LONG_LATENCY_LOADS),
    [BTS_COUNTER_SET_STALLS_FRONTEND] =
        BTS_EVENT_GENERIC("stalled_frontend_cycles",
                           PERF_COUNT_HW_STALLED_CYCLES_FRONTEND),
    [BTS_COUNTER_SET_STALLS_BACKEND] =
        BTS_EVENT_GENERIC("stalled_backend_cycles",
                           PERF_COUNT_HW_STALLED_CYCLES_BACKEND),
    [BTS_COUNTER_SET_STALLS_L1D_MISS] =
        BTS_EVENT_RAW("stalls_l1d_miss", STALLS_L1D_MISS),
    [BTS_COUNTER_SET_STALLS_MEM_ANY] =
        BTS_EVENT_RAW("stalls_mem_any", STALLS_MEM_ANY),
    [BTS_COUNTER_SET_RECOVERY_MACHINE_CLEARS] =
        BTS_EVENT_RAW("machine_clears", MACHINE_CLEARS),
    [BTS_COUNTER_SET_RECOVERY_MEMORY_ORDERING] =
        BTS_EVENT_RAW("memory_ordering_clears", MEMORY_ORDERING_CLEARS),
    [BTS_COUNTER_SET_RECOVERY_CYCLES] =
        BTS_EVENT_RAW("recovery_cycles", RECOVERY_CYCLES),
    [BTS_COUNTER_SET_RECOVERY_CYCLES_ANY] =
        BTS_EVENT_RAW("recovery_cycles_any", RECOVERY_CYCLES_ANY),
    [BTS_COUNTER_SET_UOPS_RETIRED] =
        BTS_EVENT_RAW("uops_retired_slots", UOPS_RETIRED_SLOTS),
    [BTS_COUNTER_SET_UOPS_ISSUED] =
        BTS_EVENT_RAW("uops_issued_any", UOPS_ISSUED_ANY),
    [BTS_COUNTER_SET_UOPS_EXECUTED] =
        BTS_EVENT_RAW("uops_executed_thread", UOPS_EXECUTED_THREAD),
    [BTS_COUNTER_SET_FRONTEND_UOPS_UNDELIVERED] =
        BTS_EVENT_RAW("idq_uops_not_delivered", IDQ_UOPS_NOT_DELIVERED),
    [BTS_COUNTER_SET_FRONTEND_MITE_UOPS] =
        BTS_EVENT_RAW("mite_uops", IDQ_MITE_UOPS),
    [BTS_COUNTER_SET_FRONTEND_DSB_UOPS] =
        BTS_EVENT_RAW("dsb_uops", IDQ_DSB_UOPS),
    [BTS_COUNTER_SET_FRONTEND_MS_UOPS] =
        BTS_EVENT_RAW("microcode_uops", IDQ_MS_UOPS),
    [BTS_COUNTER_SET_BRANCH_CONDITIONAL] =
        BTS_EVENT_RAW("conditional_branches", BR_CONDITIONAL),
    [BTS_COUNTER_SET_BRANCH_CONDITIONAL_TAKEN] =
        BTS_EVENT_RAW("conditional_branches_taken", BR_CONDITIONAL_TAKEN),
    [BTS_COUNTER_SET_BRANCH_CONDITIONAL_NOT_TAKEN] =
        BTS_EVENT_RAW("conditional_branches_not_taken", BR_CONDITIONAL_NOT_TAKEN),
    [BTS_COUNTER_SET_BRANCH_MISPRED_CONDITIONAL] =
        BTS_EVENT_RAW("conditional_branch_mispredicts", BR_MISPRED_CONDITIONAL),
    [BTS_COUNTER_SET_RESOURCE_STALLS_SCOREBOARD] =
        BTS_EVENT_RAW("resource_stalls_scoreboard", RESOURCE_STALLS_SCOREBOARD),
    [BTS_COUNTER_SET_RESOURCE_STALLS_STORE_BUFFER] =
        BTS_EVENT_RAW("resource_stalls_store_buffer", RESOURCE_STALLS_STORE_BUFFER),
    [BTS_COUNTER_SET_EXECUTION_BOUND_LOADS] =
        BTS_EVENT_RAW("execution_bound_on_loads", EXECUTION_BOUND_LOADS),
};

static bts_event_desc bts_events[BTS_HPC_EVENT_COUNT];

static int bts_fds[BTS_HPC_EVENT_COUNT] = {-1, -1};
static uint64_t bts_ids[BTS_HPC_EVENT_COUNT];
static uint32_t bts_requested_mask;
static uint32_t bts_available_mask;
static uint32_t bts_open_error_mask;
static int bts_hpc_ready;
static bts_hpc_snapshot bts_snapshot;

int bts_select_counter_set(unsigned int counter_set) {
    static const bts_event_desc cycles =
        BTS_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES);

    if (counter_set == 0u || counter_set > BTS_COUNTER_SET_COUNT) {
        return -EINVAL;
    }
    if (bts_hpc_ready) {
        return -EBUSY;
    }
    bts_events[0] = cycles;
    bts_events[1] = bts_second_events[counter_set];
    return 0;
}

static long bts_perf_event_open(struct perf_event_attr *attr,
                                pid_t pid,
                                int cpu,
                                int group_fd,
                                unsigned long flags) {
    return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static void bts_close_all(void) {
    unsigned int i;
    for (i = 0; i < BTS_HPC_EVENT_COUNT; ++i) {
        if (bts_fds[i] >= 0) {
            close(bts_fds[i]);
            bts_fds[i] = -1;
        }
        bts_ids[i] = 0;
    }
    bts_requested_mask = 0;
    bts_available_mask = 0;
    bts_open_error_mask = 0;
    bts_hpc_ready = 0;
}

int bts_hpc_init(void) {
    struct perf_event_attr attr;
    int leader = -1;
    unsigned int i;

    bts_close_all();
    memset(&bts_snapshot, 0, sizeof(bts_snapshot));

    for (i = 0; i < BTS_HPC_EVENT_COUNT; ++i) {
        int saved;

        if (!bts_events[i].available) {
            continue;
        }

        bts_requested_mask |= (uint32_t)(1u << i);
        memset(&attr, 0, sizeof(attr));
        attr.size = sizeof(attr);
        attr.type = bts_events[i].type;
        attr.config = bts_events[i].config;
        attr.config1 = bts_events[i].config1;
        attr.config2 = bts_events[i].config2;
        attr.precise_ip = bts_events[i].precise_ip;
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

        bts_fds[i] = (int)bts_perf_event_open(
            &attr, 0, -1, leader, PERF_FLAG_FD_CLOEXEC);

        if (bts_fds[i] < 0) {
            saved = errno;
            if (i == 0u) {
                bts_close_all();
                bts_snapshot.error_code = -saved;
                return -saved;
            }
            bts_open_error_mask |= (uint32_t)(1u << i);
            continue;
        }

        if (i == 0u) {
            leader = bts_fds[i];
        }

        if (ioctl(bts_fds[i], PERF_EVENT_IOC_ID, &bts_ids[i]) != 0) {
            saved = errno;
            close(bts_fds[i]);
            bts_fds[i] = -1;
            if (i == 0u) {
                bts_close_all();
                bts_snapshot.error_code = -saved;
                return -saved;
            }
            bts_open_error_mask |= (uint32_t)(1u << i);
            continue;
        }

        bts_available_mask |= (uint32_t)(1u << i);
    }

    if ((bts_available_mask & UINT32_C(0x1)) != UINT32_C(0x1)) {
        bts_close_all();
        bts_snapshot.error_code = -ENODEV;
        return -ENODEV;
    }

    bts_snapshot.requested_mask = bts_requested_mask;
    bts_snapshot.available_mask = bts_available_mask;
    bts_snapshot.open_error_mask = bts_open_error_mask;
    bts_hpc_ready = 1;
    return 0;
}

void bts_hpc_close(void) {
    bts_close_all();
}

const char *bts_event_name(unsigned int index) {
    return index < BTS_HPC_EVENT_COUNT ? bts_events[index].name : "unknown";
}

void bts_get_hpc_snapshot(bts_hpc_snapshot *out) {
    if (out != NULL) {
        *out = bts_snapshot;
    }
}

typedef struct {
    uint64_t value;
    uint64_t id;
} bts_read_value;

typedef struct {
    uint64_t nr;
    uint64_t time_enabled;
    uint64_t time_running;
    bts_read_value values[BTS_HPC_EVENT_COUNT];
} bts_group_read;

static inline void bts_barrier(void) {
    __asm__ volatile("" ::: "memory");
}

static inline void bts_hpc_begin(void) {
    bts_snapshot.error_code = 0;
    bts_barrier();
    if (ioctl(bts_fds[0], PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP) != 0) {
        bts_snapshot.error_code = -errno;
    }
    if (ioctl(bts_fds[0], PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP) != 0) {
        bts_snapshot.error_code = -errno;
    }
    bts_barrier();
}

static void bts_hpc_end(void) {
    bts_group_read data;
    ssize_t got;
    unsigned int i;
    unsigned int j;

    bts_barrier();
    if (ioctl(bts_fds[0], PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP) != 0) {
        bts_snapshot.error_code = -errno;
    }
    bts_barrier();

    memset(&data, 0, sizeof(data));
    got = read(bts_fds[0], &data, sizeof(data));

    bts_snapshot.sequence++;
    bts_snapshot.requested_mask = bts_requested_mask;
    bts_snapshot.available_mask = bts_available_mask;
    bts_snapshot.open_error_mask = bts_open_error_mask;
    bts_snapshot.valid_mask = 0;
    memset(bts_snapshot.values, 0, sizeof(bts_snapshot.values));

    if (got < (ssize_t)(3u * sizeof(uint64_t))) {
        bts_snapshot.error_code = got < 0 ? -errno : -EIO;
        return;
    }

    bts_snapshot.time_enabled = data.time_enabled;
    bts_snapshot.time_running = data.time_running;
    if (data.nr > BTS_HPC_EVENT_COUNT) {
        data.nr = BTS_HPC_EVENT_COUNT;
    }

    for (i = 0; i < data.nr; ++i) {
        for (j = 0; j < BTS_HPC_EVENT_COUNT; ++j) {
            if (data.values[i].id == bts_ids[j]) {
                bts_snapshot.values[j] = data.values[i].value;
                bts_snapshot.valid_mask |= (uint32_t)(1u << j);
                break;
            }
        }
    }
}


static const uint64_t bts_round_constants[24] = {
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

static const unsigned int bts_rotation[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const unsigned int bts_pilane[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

static inline uint64_t bts_rol64(uint64_t x, unsigned int shift) {
    return (x << shift) | (x >> (64u - shift));
}

static void bts_keccakf1600(uint64_t state[25]) {
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
            t = bc[(i + 4u) % 5u] ^ bts_rol64(bc[(i + 1u) % 5u], 1u);
            for (j = 0; j < 25u; j += 5u) {
                state[j + i] ^= t;
            }
        }
        t = state[1];
        for (i = 0; i < 24u; ++i) {
            j = bts_pilane[i];
            bc[0] = state[j];
            state[j] = bts_rol64(t, bts_rotation[i]);
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
        state[0] ^= bts_round_constants[round];
    }
}

static inline uint64_t bts_load64(const uint8_t *src) {
    uint64_t value = 0;
    unsigned int i;
    for (i = 0; i < 8u; ++i) {
        value |= (uint64_t)src[i] << (8u * i);
    }
    return value;
}

static inline void bts_store64(uint8_t *dst, uint64_t value) {
    unsigned int i;
    for (i = 0; i < 8u; ++i) {
        dst[i] = (uint8_t)(value >> (8u * i));
    }
}

static inline void bts_absorb_full_block(uint64_t state[25], const uint8_t *block) {
    unsigned int i;
    for (i = 0; i < BTS_SHAKE256_RATE / 8u; ++i) {
        state[i] ^= bts_load64(block + 8u * i);
    }
    bts_keccakf1600(state);
}

static inline void bts_absorb_tail_and_squeeze(
    uint8_t output[BTS_SHAKE_OUTPUT_BYTES],
    uint64_t state[25],
    const uint8_t tail[BTS_SHAKE_TAIL_BYTES]) {
    uint8_t block[BTS_SHAKE256_RATE];
    unsigned int i;
    memset(block, 0, sizeof(block));
    memcpy(block, tail, BTS_SHAKE_TAIL_BYTES);
    block[BTS_SHAKE_TAIL_BYTES] ^= UINT8_C(0x1f);
    block[BTS_SHAKE256_RATE - 1u] ^= UINT8_C(0x80);
    for (i = 0; i < BTS_SHAKE256_RATE / 8u; ++i) {
        state[i] ^= bts_load64(block + 8u * i);
    }
    bts_keccakf1600(state);
    for (i = 0; i < BTS_SHAKE_OUTPUT_BYTES / 8u; ++i) {
        bts_store64(output + 8u * i, state[i]);
    }
}

/* Canonical path: absorb all eight full blocks, then the unchanged tail. */
BTS_NOINLINE
void bts_shake_baseline_target(bts_job *job) {
    uint64_t state[25] = {0};
    unsigned int block;
    for (block = 0; block < BTS_SHAKE_FULL_BLOCKS; ++block) {
        bts_absorb_full_block(state, job->input + block * BTS_SHAKE256_RATE);
    }
    bts_absorb_tail_and_squeeze(
        job->output->shake, state,
        job->input + BTS_SHAKE_FULL_BLOCKS * BTS_SHAKE256_RATE);
}

/* Attack T1: the full-block absorb loop terminates after block 3. */
BTS_NOINLINE
void bts_shake_abort_target(bts_job *job) {
    uint64_t state[25] = {0};
    unsigned int block;
    for (block = 0; block < BTS_SHAKE_ABORT_AFTER_BLOCKS; ++block) {
        bts_absorb_full_block(state, job->input + block * BTS_SHAKE256_RATE);
    }
    bts_absorb_tail_and_squeeze(
        job->output->shake, state,
        job->input + BTS_SHAKE_FULL_BLOCKS * BTS_SHAKE256_RATE);
}

/* Attack T2: exactly block 3 is omitted; preceding and following blocks run. */
BTS_NOINLINE
void bts_shake_skip_block_target(bts_job *job) {
    uint64_t state[25] = {0};
    unsigned int block;
    for (block = 0; block < BTS_SHAKE_SKIP_BLOCK; ++block) {
        bts_absorb_full_block(state, job->input + block * BTS_SHAKE256_RATE);
    }
    for (block = BTS_SHAKE_SKIP_BLOCK + 1u; block < BTS_SHAKE_FULL_BLOCKS; ++block) {
        bts_absorb_full_block(state, job->input + block * BTS_SHAKE256_RATE);
    }
    bts_absorb_tail_and_squeeze(
        job->output->shake, state,
        job->input + BTS_SHAKE_FULL_BLOCKS * BTS_SHAKE256_RATE);
}

static inline void bts_polyz_group_normal(int32_t *out, const uint8_t *a) {
    uint32_t t0;
    uint32_t t1;
    uint32_t t2;
    uint32_t t3;
    t0  = a[0];
    t0 |= (uint32_t)a[1] << 8;
    t0 |= (uint32_t)a[2] << 16;
    t0 &= UINT32_C(0x3ffff);
    t1  = a[2] >> 2;
    t1 |= (uint32_t)a[3] << 6;
    t1 |= (uint32_t)a[4] << 14;
    t1 &= UINT32_C(0x3ffff);
    t2  = a[4] >> 4;
    t2 |= (uint32_t)a[5] << 4;
    t2 |= (uint32_t)a[6] << 12;
    t2 &= UINT32_C(0x3ffff);
    t3  = a[6] >> 6;
    t3 |= (uint32_t)a[7] << 2;
    t3 |= (uint32_t)a[8] << 10;
    t3 &= UINT32_C(0x3ffff);
    out[0] = (int32_t)BTS_GAMMA1 - (int32_t)t0;
    out[1] = (int32_t)BTS_GAMMA1 - (int32_t)t1;
    out[2] = (int32_t)BTS_GAMMA1 - (int32_t)t2;
    out[3] = (int32_t)BTS_GAMMA1 - (int32_t)t3;
}

/*
 * The target coefficient uses explicit r12d dataflow so a skipped load does
 * not let the compiler delete the following shift/OR instructions. r12d is
 * preloaded outside the PMU window. The canonical helper overwrites it with
 * a[3]; the faulty helper enters directly at the dependent operations.
 */
BTS_NOINLINE
static void bts_polyz_group_target_baseline(int32_t *out, const uint8_t *a) {
    uint32_t t0;
    uint32_t t1;
    uint32_t t2;
    uint32_t t3;
    t0  = a[0];
    t0 |= (uint32_t)a[1] << 8;
    t0 |= (uint32_t)a[2] << 16;
    t0 &= UINT32_C(0x3ffff);
    t1  = a[2] >> 2;
    __asm__ volatile(
        "movzbl 3(%[src]), %%r12d\n\t"
        "shll $6, %%r12d\n\t"
        "orl %%r12d, %[acc]\n\t"
        : [acc] "+r"(t1)
        : [src] "r"(a)
        : "r12", "cc", "memory");
    t1 |= (uint32_t)a[4] << 14;
    t1 &= UINT32_C(0x3ffff);
    t2  = a[4] >> 4;
    t2 |= (uint32_t)a[5] << 4;
    t2 |= (uint32_t)a[6] << 12;
    t2 &= UINT32_C(0x3ffff);
    t3  = a[6] >> 6;
    t3 |= (uint32_t)a[7] << 2;
    t3 |= (uint32_t)a[8] << 10;
    t3 &= UINT32_C(0x3ffff);
    out[0] = (int32_t)BTS_GAMMA1 - (int32_t)t0;
    out[1] = (int32_t)BTS_GAMMA1 - (int32_t)t1;
    out[2] = (int32_t)BTS_GAMMA1 - (int32_t)t2;
    out[3] = (int32_t)BTS_GAMMA1 - (int32_t)t3;
}

BTS_NOINLINE
static void bts_polyz_group_target_skipped_load(int32_t *out, const uint8_t *a) {
    uint32_t t0;
    uint32_t t1;
    uint32_t t2;
    uint32_t t3;
    t0  = a[0];
    t0 |= (uint32_t)a[1] << 8;
    t0 |= (uint32_t)a[2] << 16;
    t0 &= UINT32_C(0x3ffff);
    t1  = a[2] >> 2;
    __asm__ volatile(
        /* The canonical movzbl 3(src), r12d is the one skipped instruction. */
        "shll $6, %%r12d\n\t"
        "orl %%r12d, %[acc]\n\t"
        : [acc] "+r"(t1)
        :
        : "r12", "cc", "memory");
    t1 |= (uint32_t)a[4] << 14;
    t1 &= UINT32_C(0x3ffff);
    t2  = a[4] >> 4;
    t2 |= (uint32_t)a[5] << 4;
    t2 |= (uint32_t)a[6] << 12;
    t2 &= UINT32_C(0x3ffff);
    t3  = a[6] >> 6;
    t3 |= (uint32_t)a[7] << 2;
    t3 |= (uint32_t)a[8] << 10;
    t3 &= UINT32_C(0x3ffff);
    out[0] = (int32_t)BTS_GAMMA1 - (int32_t)t0;
    out[1] = (int32_t)BTS_GAMMA1 - (int32_t)t1;
    out[2] = (int32_t)BTS_GAMMA1 - (int32_t)t2;
    out[3] = (int32_t)BTS_GAMMA1 - (int32_t)t3;
}

void bts_preload_fault_register(uint32_t value) {
    __asm__ volatile("movl %0, %%r12d" : : "r"(value) : "r12");
}

BTS_NOINLINE
void bts_polyz_baseline_target(bts_job *job) {
    unsigned int group;
    for (group = 0; group < BTS_POLYZ_TARGET_GROUP; ++group) {
        bts_polyz_group_normal(job->output->coeffs + 4u * group,
                              job->input + 9u * group);
    }
    bts_polyz_group_target_baseline(
        job->output->coeffs + 4u * BTS_POLYZ_TARGET_GROUP,
        job->input + 9u * BTS_POLYZ_TARGET_GROUP);
    for (group = BTS_POLYZ_TARGET_GROUP + 1u; group < BTS_N / 4u; ++group) {
        bts_polyz_group_normal(job->output->coeffs + 4u * group,
                              job->input + 9u * group);
    }
}

BTS_NOINLINE
void bts_polyz_zero_load_target(bts_job *job) {
    unsigned int group;
    for (group = 0; group < BTS_POLYZ_TARGET_GROUP; ++group) {
        bts_polyz_group_normal(job->output->coeffs + 4u * group,
                              job->input + 9u * group);
    }
    bts_polyz_group_target_skipped_load(
        job->output->coeffs + 4u * BTS_POLYZ_TARGET_GROUP,
        job->input + 9u * BTS_POLYZ_TARGET_GROUP);
    for (group = BTS_POLYZ_TARGET_GROUP + 1u; group < BTS_N / 4u; ++group) {
        bts_polyz_group_normal(job->output->coeffs + 4u * group,
                              job->input + 9u * group);
    }
}

BTS_NOINLINE
void bts_polyz_stale_load_target(bts_job *job) {
    unsigned int group;
    for (group = 0; group < BTS_POLYZ_TARGET_GROUP; ++group) {
        bts_polyz_group_normal(job->output->coeffs + 4u * group,
                              job->input + 9u * group);
    }
    bts_polyz_group_target_skipped_load(
        job->output->coeffs + 4u * BTS_POLYZ_TARGET_GROUP,
        job->input + 9u * BTS_POLYZ_TARGET_GROUP);
    for (group = BTS_POLYZ_TARGET_GROUP + 1u; group < BTS_N / 4u; ++group) {
        bts_polyz_group_normal(job->output->coeffs + 4u * group,
                              job->input + 9u * group);
    }
}

#define BTS_DEFINE_MEASURE_WRAPPER(name_, target_) \
    BTS_NOINLINE void name_(bts_job *job) { \
        if (!bts_hpc_ready) { \
            bts_snapshot.error_code = -ENODEV; \
            return; \
        } \
        bts_preload_fault_register(job->fault_register_value); \
        bts_hpc_begin(); \
        target_(job); \
        bts_hpc_end(); \
    }

BTS_DEFINE_MEASURE_WRAPPER(bts_measure_shake_baseline, bts_shake_baseline_target)
BTS_DEFINE_MEASURE_WRAPPER(bts_measure_shake_abort, bts_shake_abort_target)
BTS_DEFINE_MEASURE_WRAPPER(bts_measure_shake_skip_block, bts_shake_skip_block_target)
BTS_DEFINE_MEASURE_WRAPPER(bts_measure_polyz_baseline, bts_polyz_baseline_target)
BTS_DEFINE_MEASURE_WRAPPER(bts_measure_polyz_zero_load, bts_polyz_zero_load_target)
BTS_DEFINE_MEASURE_WRAPPER(bts_measure_polyz_stale_load, bts_polyz_stale_load_target)
