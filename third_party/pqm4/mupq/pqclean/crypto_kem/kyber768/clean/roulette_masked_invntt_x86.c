#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "roulette_masked_invntt_x86.h"
#include "ntt.h"
#include "reduce.h"
#include "microarch_events_generated.h"

#include <errno.h>
#include <linux/perf_event.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef ROU_PMU_TYPE
#define ROU_PMU_TYPE 4u
#endif

#ifndef ROU_LOAD_CONFIG
#define ROU_LOAD_CONFIG UINT64_C(0x81d0)
#endif

#ifndef ROU_STORE_CONFIG
#define ROU_STORE_CONFIG UINT64_C(0x82d0)
#endif



#if defined(__GNUC__) || defined(__clang__)
#define ROU_NOINLINE __attribute__((noinline, noclone, used))
#else
#define ROU_NOINLINE
#endif

typedef struct {
    const char *name;
    uint32_t type;
    uint64_t config;
    uint64_t config1;
    uint64_t config2;
    uint32_t precise_ip;
    uint32_t available;
} rou_event_desc;

#define ROU_EVENT_GENERIC(name_, config_) \
    {name_, PERF_TYPE_HARDWARE, config_, UINT64_C(0), UINT64_C(0), 0u, 1u}

#define ROU_EVENT_RAW(name_, macro_) \
    { \
        name_, \
        ROU_EVT_##macro_##_TYPE, \
        ROU_EVT_##macro_##_CONFIG, \
        ROU_EVT_##macro_##_CONFIG1, \
        ROU_EVT_##macro_##_CONFIG2, \
        ROU_EVT_##macro_##_PRECISE_IP, \
        ROU_EVT_##macro_##_AVAILABLE \
    }

#define ROU_CACHE_CONFIG(cache, op, result) \
    ((uint64_t)(cache) | ((uint64_t)(op) << 8) | ((uint64_t)(result) << 16))

/*
 * Retained only as a readable mapping from the previous compile-time build.
 * The active table below selects the same events at runtime so every
 * baseline, attack, and PMU pass uses exactly one ELF executable.
 */
#if 0
#if ROU_COUNTER_SET == ROU_COUNTER_SET_STRUCTURAL_INSTRUCTIONS
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_GENERIC("instructions", PERF_COUNT_HW_INSTRUCTIONS),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_STRUCTURAL_BRANCHES
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_GENERIC("branches", PERF_COUNT_HW_BRANCH_INSTRUCTIONS),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_STRUCTURAL_BRANCH_MISSES
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_GENERIC("branch_misses", PERF_COUNT_HW_BRANCH_MISSES),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_STRUCTURAL_LOADS
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"retired_loads", ROU_PMU_TYPE, ROU_LOAD_CONFIG, 0, 0, 0, 1},
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_STRUCTURAL_STORES
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"retired_stores", ROU_PMU_TYPE, ROU_STORE_CONFIG, 0, 0, 0, 1},
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_CACHE_L1D
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"l1d_read_misses", PERF_TYPE_HW_CACHE,
        ROU_CACHE_CONFIG(PERF_COUNT_HW_CACHE_L1D, PERF_COUNT_HW_CACHE_OP_READ,
                         PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_CACHE_L1I
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"l1i_read_misses", PERF_TYPE_HW_CACHE,
        ROU_CACHE_CONFIG(PERF_COUNT_HW_CACHE_L1I, PERF_COUNT_HW_CACHE_OP_READ,
                         PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_CACHE_LLC
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"llc_read_misses", PERF_TYPE_HW_CACHE,
        ROU_CACHE_CONFIG(PERF_COUNT_HW_CACHE_LL, PERF_COUNT_HW_CACHE_OP_READ,
                         PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_CACHE_DTLB
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"dtlb_read_misses", PERF_TYPE_HW_CACHE,
        ROU_CACHE_CONFIG(PERF_COUNT_HW_CACHE_DTLB, PERF_COUNT_HW_CACHE_OP_READ,
                         PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_CACHE_REFERENCES
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_GENERIC("cache_references", PERF_COUNT_HW_CACHE_REFERENCES),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_CACHE_MISSES
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_GENERIC("cache_misses", PERF_COUNT_HW_CACHE_MISSES),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_CACHE_L1D_REPLACEMENTS
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("l1d_replacements", L1D_REPLACEMENTS),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_CACHE_L2_REQUEST_MISSES
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("l2_request_misses", L2_REQUEST_MISSES),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_LOAD_L1_HIT
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("load_l1_hit", LOAD_L1_HIT),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_LOAD_L2_HIT
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("load_l2_hit", LOAD_L2_HIT),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_LOAD_L3_HIT
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("load_l3_hit", LOAD_L3_HIT),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_LOAD_L1_MISS
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("load_l1_miss", LOAD_L1_MISS),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_LOAD_L2_MISS
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("load_l2_miss", LOAD_L2_MISS),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_LOAD_L3_MISS
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("load_l3_miss", LOAD_L3_MISS),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_LONG_LATENCY_LOADS
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("long_latency_loads", LONG_LATENCY_LOADS),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_STALLS_FRONTEND
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_GENERIC("stalled_frontend_cycles", PERF_COUNT_HW_STALLED_CYCLES_FRONTEND),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_STALLS_BACKEND
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_GENERIC("stalled_backend_cycles", PERF_COUNT_HW_STALLED_CYCLES_BACKEND),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_STALLS_L1D_MISS
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("stalls_l1d_miss", STALLS_L1D_MISS),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_STALLS_MEM_ANY
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("stalls_mem_any", STALLS_MEM_ANY),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_RECOVERY_MACHINE_CLEARS
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("machine_clears", MACHINE_CLEARS),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_RECOVERY_MEMORY_ORDERING
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("memory_ordering_clears", MEMORY_ORDERING_CLEARS),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_RECOVERY_CYCLES
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("recovery_cycles", RECOVERY_CYCLES),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_RECOVERY_CYCLES_ANY
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("recovery_cycles_any", RECOVERY_CYCLES_ANY),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_UOPS_RETIRED
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("uops_retired_slots", UOPS_RETIRED_SLOTS),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_UOPS_ISSUED
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("uops_issued_any", UOPS_ISSUED_ANY),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_UOPS_EXECUTED
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("uops_executed_thread", UOPS_EXECUTED_THREAD),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_FRONTEND_UOPS_UNDELIVERED
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("idq_uops_not_delivered", IDQ_UOPS_NOT_DELIVERED),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_FRONTEND_MITE_UOPS
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("mite_uops", IDQ_MITE_UOPS),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_FRONTEND_DSB_UOPS
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("dsb_uops", IDQ_DSB_UOPS),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_FRONTEND_MS_UOPS
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("microcode_uops", IDQ_MS_UOPS),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_BRANCH_CONDITIONAL
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("conditional_branches", BR_CONDITIONAL),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_BRANCH_CONDITIONAL_TAKEN
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("conditional_branches_taken", BR_CONDITIONAL_TAKEN),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_BRANCH_CONDITIONAL_NOT_TAKEN
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("conditional_branches_not_taken", BR_CONDITIONAL_NOT_TAKEN),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_BRANCH_MISPRED_CONDITIONAL
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("conditional_branch_mispredicts", BR_MISPRED_CONDITIONAL),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_RESOURCE_STALLS_SCOREBOARD
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("resource_stalls_scoreboard", RESOURCE_STALLS_SCOREBOARD),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_RESOURCE_STALLS_STORE_BUFFER
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("resource_stalls_store_buffer", RESOURCE_STALLS_STORE_BUFFER),
};
#elif ROU_COUNTER_SET == ROU_COUNTER_SET_EXECUTION_BOUND_LOADS
static const rou_event_desc rou_events[ROU_HPC_EVENT_COUNT] = {
    ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    ROU_EVENT_RAW("execution_bound_on_loads", EXECUTION_BOUND_LOADS),
};
#else
#error "invalid ROU_COUNTER_SET"
#endif
#endif

static const rou_event_desc rou_second_events[ROU_COUNTER_SET_COUNT + 1u] = {
    [ROU_COUNTER_SET_STRUCTURAL_INSTRUCTIONS] =
        ROU_EVENT_GENERIC("instructions", PERF_COUNT_HW_INSTRUCTIONS),
    [ROU_COUNTER_SET_STRUCTURAL_BRANCHES] =
        ROU_EVENT_GENERIC("branches", PERF_COUNT_HW_BRANCH_INSTRUCTIONS),
    [ROU_COUNTER_SET_STRUCTURAL_BRANCH_MISSES] =
        ROU_EVENT_GENERIC("branch_misses", PERF_COUNT_HW_BRANCH_MISSES),
    [ROU_COUNTER_SET_STRUCTURAL_LOADS] =
        {"retired_loads", ROU_PMU_TYPE, ROU_LOAD_CONFIG, 0, 0, 0, 1},
    [ROU_COUNTER_SET_STRUCTURAL_STORES] =
        {"retired_stores", ROU_PMU_TYPE, ROU_STORE_CONFIG, 0, 0, 0, 1},
    [ROU_COUNTER_SET_CACHE_L1D] = {
        "l1d_read_misses", PERF_TYPE_HW_CACHE,
        ROU_CACHE_CONFIG(PERF_COUNT_HW_CACHE_L1D, PERF_COUNT_HW_CACHE_OP_READ,
                          PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
    [ROU_COUNTER_SET_CACHE_L1I] = {
        "l1i_read_misses", PERF_TYPE_HW_CACHE,
        ROU_CACHE_CONFIG(PERF_COUNT_HW_CACHE_L1I, PERF_COUNT_HW_CACHE_OP_READ,
                          PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
    [ROU_COUNTER_SET_CACHE_LLC] = {
        "llc_read_misses", PERF_TYPE_HW_CACHE,
        ROU_CACHE_CONFIG(PERF_COUNT_HW_CACHE_LL, PERF_COUNT_HW_CACHE_OP_READ,
                          PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
    [ROU_COUNTER_SET_CACHE_DTLB] = {
        "dtlb_read_misses", PERF_TYPE_HW_CACHE,
        ROU_CACHE_CONFIG(PERF_COUNT_HW_CACHE_DTLB, PERF_COUNT_HW_CACHE_OP_READ,
                          PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
    [ROU_COUNTER_SET_CACHE_REFERENCES] =
        ROU_EVENT_GENERIC("cache_references", PERF_COUNT_HW_CACHE_REFERENCES),
    [ROU_COUNTER_SET_CACHE_MISSES] =
        ROU_EVENT_GENERIC("cache_misses", PERF_COUNT_HW_CACHE_MISSES),
    [ROU_COUNTER_SET_CACHE_L1D_REPLACEMENTS] =
        ROU_EVENT_RAW("l1d_replacements", L1D_REPLACEMENTS),
    [ROU_COUNTER_SET_CACHE_L2_REQUEST_MISSES] =
        ROU_EVENT_RAW("l2_request_misses", L2_REQUEST_MISSES),
    [ROU_COUNTER_SET_LOAD_L1_HIT] =
        ROU_EVENT_RAW("load_l1_hit", LOAD_L1_HIT),
    [ROU_COUNTER_SET_LOAD_L2_HIT] =
        ROU_EVENT_RAW("load_l2_hit", LOAD_L2_HIT),
    [ROU_COUNTER_SET_LOAD_L3_HIT] =
        ROU_EVENT_RAW("load_l3_hit", LOAD_L3_HIT),
    [ROU_COUNTER_SET_LOAD_L1_MISS] =
        ROU_EVENT_RAW("load_l1_miss", LOAD_L1_MISS),
    [ROU_COUNTER_SET_LOAD_L2_MISS] =
        ROU_EVENT_RAW("load_l2_miss", LOAD_L2_MISS),
    [ROU_COUNTER_SET_LOAD_L3_MISS] =
        ROU_EVENT_RAW("load_l3_miss", LOAD_L3_MISS),
    [ROU_COUNTER_SET_LONG_LATENCY_LOADS] =
        ROU_EVENT_RAW("long_latency_loads", LONG_LATENCY_LOADS),
    [ROU_COUNTER_SET_STALLS_FRONTEND] =
        ROU_EVENT_GENERIC("stalled_frontend_cycles",
                           PERF_COUNT_HW_STALLED_CYCLES_FRONTEND),
    [ROU_COUNTER_SET_STALLS_BACKEND] =
        ROU_EVENT_GENERIC("stalled_backend_cycles",
                           PERF_COUNT_HW_STALLED_CYCLES_BACKEND),
    [ROU_COUNTER_SET_STALLS_L1D_MISS] =
        ROU_EVENT_RAW("stalls_l1d_miss", STALLS_L1D_MISS),
    [ROU_COUNTER_SET_STALLS_MEM_ANY] =
        ROU_EVENT_RAW("stalls_mem_any", STALLS_MEM_ANY),
    [ROU_COUNTER_SET_RECOVERY_MACHINE_CLEARS] =
        ROU_EVENT_RAW("machine_clears", MACHINE_CLEARS),
    [ROU_COUNTER_SET_RECOVERY_MEMORY_ORDERING] =
        ROU_EVENT_RAW("memory_ordering_clears", MEMORY_ORDERING_CLEARS),
    [ROU_COUNTER_SET_RECOVERY_CYCLES] =
        ROU_EVENT_RAW("recovery_cycles", RECOVERY_CYCLES),
    [ROU_COUNTER_SET_RECOVERY_CYCLES_ANY] =
        ROU_EVENT_RAW("recovery_cycles_any", RECOVERY_CYCLES_ANY),
    [ROU_COUNTER_SET_UOPS_RETIRED] =
        ROU_EVENT_RAW("uops_retired_slots", UOPS_RETIRED_SLOTS),
    [ROU_COUNTER_SET_UOPS_ISSUED] =
        ROU_EVENT_RAW("uops_issued_any", UOPS_ISSUED_ANY),
    [ROU_COUNTER_SET_UOPS_EXECUTED] =
        ROU_EVENT_RAW("uops_executed_thread", UOPS_EXECUTED_THREAD),
    [ROU_COUNTER_SET_FRONTEND_UOPS_UNDELIVERED] =
        ROU_EVENT_RAW("idq_uops_not_delivered", IDQ_UOPS_NOT_DELIVERED),
    [ROU_COUNTER_SET_FRONTEND_MITE_UOPS] =
        ROU_EVENT_RAW("mite_uops", IDQ_MITE_UOPS),
    [ROU_COUNTER_SET_FRONTEND_DSB_UOPS] =
        ROU_EVENT_RAW("dsb_uops", IDQ_DSB_UOPS),
    [ROU_COUNTER_SET_FRONTEND_MS_UOPS] =
        ROU_EVENT_RAW("microcode_uops", IDQ_MS_UOPS),
    [ROU_COUNTER_SET_BRANCH_CONDITIONAL] =
        ROU_EVENT_RAW("conditional_branches", BR_CONDITIONAL),
    [ROU_COUNTER_SET_BRANCH_CONDITIONAL_TAKEN] =
        ROU_EVENT_RAW("conditional_branches_taken", BR_CONDITIONAL_TAKEN),
    [ROU_COUNTER_SET_BRANCH_CONDITIONAL_NOT_TAKEN] =
        ROU_EVENT_RAW("conditional_branches_not_taken", BR_CONDITIONAL_NOT_TAKEN),
    [ROU_COUNTER_SET_BRANCH_MISPRED_CONDITIONAL] =
        ROU_EVENT_RAW("conditional_branch_mispredicts", BR_MISPRED_CONDITIONAL),
    [ROU_COUNTER_SET_RESOURCE_STALLS_SCOREBOARD] =
        ROU_EVENT_RAW("resource_stalls_scoreboard", RESOURCE_STALLS_SCOREBOARD),
    [ROU_COUNTER_SET_RESOURCE_STALLS_STORE_BUFFER] =
        ROU_EVENT_RAW("resource_stalls_store_buffer", RESOURCE_STALLS_STORE_BUFFER),
    [ROU_COUNTER_SET_EXECUTION_BOUND_LOADS] =
        ROU_EVENT_RAW("execution_bound_on_loads", EXECUTION_BOUND_LOADS),
};

static rou_event_desc rou_events[ROU_HPC_EVENT_COUNT];

static int rou_fds[ROU_HPC_EVENT_COUNT] = {-1, -1};
static uint64_t rou_ids[ROU_HPC_EVENT_COUNT];
static uint32_t rou_requested_mask;
static uint32_t rou_available_mask;
static uint32_t rou_open_error_mask;
static int rou_hpc_ready;
static rou_hpc_snapshot rou_snapshot;

int rou_select_counter_set(unsigned int counter_set) {
    static const rou_event_desc cycles =
        ROU_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES);

    if (counter_set == 0u || counter_set > ROU_COUNTER_SET_COUNT) {
        return -EINVAL;
    }
    if (rou_hpc_ready) {
        return -EBUSY;
    }
    rou_events[0] = cycles;
    rou_events[1] = rou_second_events[counter_set];
    return 0;
}

static long rou_perf_event_open(struct perf_event_attr *attr,
                                pid_t pid,
                                int cpu,
                                int group_fd,
                                unsigned long flags) {
    return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static void rou_close_all(void) {
    unsigned int i;
    for (i = 0; i < ROU_HPC_EVENT_COUNT; ++i) {
        if (rou_fds[i] >= 0) {
            close(rou_fds[i]);
            rou_fds[i] = -1;
        }
        rou_ids[i] = 0;
    }
    rou_requested_mask = 0;
    rou_available_mask = 0;
    rou_open_error_mask = 0;
    rou_hpc_ready = 0;
}

int rou_hpc_init(void) {
    struct perf_event_attr attr;
    int leader = -1;
    unsigned int i;

    rou_close_all();
    memset(&rou_snapshot, 0, sizeof(rou_snapshot));

    for (i = 0; i < ROU_HPC_EVENT_COUNT; ++i) {
        int saved;

        if (!rou_events[i].available) {
            continue;
        }

        rou_requested_mask |= (uint32_t)(1u << i);
        memset(&attr, 0, sizeof(attr));
        attr.size = sizeof(attr);
        attr.type = rou_events[i].type;
        attr.config = rou_events[i].config;
        attr.config1 = rou_events[i].config1;
        attr.config2 = rou_events[i].config2;
        attr.precise_ip = rou_events[i].precise_ip;
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

        rou_fds[i] = (int)rou_perf_event_open(
            &attr, 0, -1, leader, PERF_FLAG_FD_CLOEXEC);

        if (rou_fds[i] < 0) {
            saved = errno;
            if (i == 0u) {
                rou_close_all();
                rou_snapshot.error_code = -saved;
                return -saved;
            }
            rou_open_error_mask |= (uint32_t)(1u << i);
            continue;
        }

        if (i == 0u) {
            leader = rou_fds[i];
        }

        if (ioctl(rou_fds[i], PERF_EVENT_IOC_ID, &rou_ids[i]) != 0) {
            saved = errno;
            close(rou_fds[i]);
            rou_fds[i] = -1;
            if (i == 0u) {
                rou_close_all();
                rou_snapshot.error_code = -saved;
                return -saved;
            }
            rou_open_error_mask |= (uint32_t)(1u << i);
            continue;
        }

        rou_available_mask |= (uint32_t)(1u << i);
    }

    if ((rou_available_mask & UINT32_C(0x1)) != UINT32_C(0x1)) {
        rou_close_all();
        rou_snapshot.error_code = -ENODEV;
        return -ENODEV;
    }

    rou_snapshot.requested_mask = rou_requested_mask;
    rou_snapshot.available_mask = rou_available_mask;
    rou_snapshot.open_error_mask = rou_open_error_mask;
    rou_hpc_ready = 1;
    return 0;
}

void rou_hpc_close(void) {
    rou_close_all();
}

const char *rou_event_name(unsigned int index) {
    return index < ROU_HPC_EVENT_COUNT ? rou_events[index].name : "unknown";
}

void rou_get_hpc_snapshot(rou_hpc_snapshot *out) {
    if (out != NULL) {
        *out = rou_snapshot;
    }
}

typedef struct {
    uint64_t value;
    uint64_t id;
} rou_read_value;

typedef struct {
    uint64_t nr;
    uint64_t time_enabled;
    uint64_t time_running;
    rou_read_value values[ROU_HPC_EVENT_COUNT];
} rou_group_read;

static inline void rou_barrier(void) {
    __asm__ volatile("" ::: "memory");
}

static inline void rou_hpc_begin(void) {
    rou_snapshot.error_code = 0;
    rou_barrier();
    if (ioctl(rou_fds[0], PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP) != 0) {
        rou_snapshot.error_code = -errno;
    }
    if (ioctl(rou_fds[0], PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP) != 0) {
        rou_snapshot.error_code = -errno;
    }
    rou_barrier();
}

static void rou_hpc_end(void) {
    rou_group_read data;
    ssize_t got;
    unsigned int i;
    unsigned int j;

    rou_barrier();
    if (ioctl(rou_fds[0], PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP) != 0) {
        rou_snapshot.error_code = -errno;
    }
    rou_barrier();

    memset(&data, 0, sizeof(data));
    got = read(rou_fds[0], &data, sizeof(data));

    rou_snapshot.sequence++;
    rou_snapshot.requested_mask = rou_requested_mask;
    rou_snapshot.available_mask = rou_available_mask;
    rou_snapshot.open_error_mask = rou_open_error_mask;
    rou_snapshot.valid_mask = 0;
    memset(rou_snapshot.values, 0, sizeof(rou_snapshot.values));

    if (got < (ssize_t)(3u * sizeof(uint64_t))) {
        rou_snapshot.error_code = got < 0 ? -errno : -EIO;
        return;
    }

    rou_snapshot.time_enabled = data.time_enabled;
    rou_snapshot.time_running = data.time_running;
    if (data.nr > ROU_HPC_EVENT_COUNT) {
        data.nr = ROU_HPC_EVENT_COUNT;
    }

    for (i = 0; i < data.nr; ++i) {
        for (j = 0; j < ROU_HPC_EVENT_COUNT; ++j) {
            if (data.values[i].id == rou_ids[j]) {
                rou_snapshot.values[j] = data.values[i].value;
                rou_snapshot.valid_mask |= (uint32_t)(1u << j);
                break;
            }
        }
    }
}



#ifndef ROU_NOINLINE
#define ROU_NOINLINE __attribute__((noinline, noclone, used))
#endif

typedef int32_t (*rou_local_target_fn)(
    int32_t a_share, int32_t b_share,
    int32_t fault_value, uint32_t flip_mask);
typedef int32_t (*rou_local_measure_fn)(
    int32_t a_share, int32_t b_share,
    int32_t fault_value, uint32_t flip_mask);

static int rou_measurement_enabled;
static int rou_reencrypt_active;
static unsigned int rou_target_coeff = 17u;
static unsigned int rou_runtime_mode = ROU_MODE_BASELINE;
static int32_t rou_selected_constant = INT32_C(0x5a5a);
static unsigned int rou_selected_flip_bit = 5u;
static uint32_t rou_mask_prng_state = UINT32_C(0x6d2b79f5);
static uint32_t rou_fault_prng_state = UINT32_C(0x726f756c);
static uint64_t rou_reencrypt_invocations;
static rou_audit_snapshot rou_audit;
static rou_local_target_fn rou_selected_target;
static rou_local_measure_fn rou_selected_measure;

static int32_t rou_mod_q(int32_t value) {
    value %= KYBER_Q;
    if (value < 0) value += KYBER_Q;
    return value;
}

static uint32_t rou_xorshift32(uint32_t *state) {
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    if (x == 0u) x = UINT32_C(0x6d2b79f5);
    *state = x;
    return x;
}

static int16_t rou_uniform_mod_q(void) {
    const uint64_t range = UINT64_C(1) << 32;
    const uint64_t limit =
        (range / (uint64_t)KYBER_Q) * (uint64_t)KYBER_Q;
    uint32_t value;
    do {
        value = rou_xorshift32(&rou_mask_prng_state);
    } while ((uint64_t)value >= limit);
    return (int16_t)(value % (uint32_t)KYBER_Q);
}

static int32_t rou_random_fault_value(int32_t normal_value) {
    int32_t value =
        (int32_t)(int16_t)rou_xorshift32(&rou_fault_prng_state);
    if (value == normal_value) {
        value = (int32_t)(int16_t)
            ((uint16_t)value ^ UINT16_C(0x4000));
    }
    return value;
}

static int16_t rou_fqmul(int16_t a, int16_t b) {
    return PQCLEAN_KYBER768_CLEAN_montgomery_reduce((int32_t)a * b);
}

static uint64_t rou_poly_tag(const poly *value) {
    uint64_t h = UINT64_C(1469598103934665603);
    unsigned int i;
    for (i = 0; i < KYBER_N; ++i) {
        uint16_t x = (uint16_t)value->coeffs[i];
        h ^= (uint8_t)x;
        h *= UINT64_C(1099511628211);
        h ^= (uint8_t)(x >> 8);
        h *= UINT64_C(1099511628211);
    }
    return h;
}

ROU_NOINLINE
int32_t rou_target_masked_add_baseline(
    int32_t a_share, int32_t b_share,
    int32_t fault_value, uint32_t flip_mask) {
    (void)fault_value;
    (void)flip_mask;
    __asm__ volatile(
        "addl %1, %0"
        : "+r"(a_share)
        : "r"(b_share)
        : "cc");
    return a_share;
}

ROU_NOINLINE
int32_t rou_target_set_masked_intermediate_constant(
    int32_t a_share, int32_t b_share,
    int32_t fault_value, uint32_t flip_mask) {
    (void)b_share;
    (void)flip_mask;
    __asm__ volatile(
        "movl %1, %0"
        : "+r"(a_share)
        : "r"(fault_value)
        : "cc");
    return a_share;
}

ROU_NOINLINE
int32_t rou_target_replace_masked_intermediate_random(
    int32_t a_share, int32_t b_share,
    int32_t fault_value, uint32_t flip_mask) {
    (void)b_share;
    (void)flip_mask;
    __asm__ volatile(
        "movl %1, %0"
        : "+r"(a_share)
        : "r"(fault_value)
        : "cc");
    return a_share;
}

#define ROU_DEFINE_MEASURE_WRAPPER(name_, target_) \
    ROU_NOINLINE int32_t name_( \
        int32_t a_share, int32_t b_share, \
        int32_t fault_value, uint32_t flip_mask) { \
        int32_t result; \
        if (!rou_hpc_ready) { \
            rou_snapshot.error_code = -ENODEV; \
            return a_share; \
        } \
        rou_hpc_begin(); \
        result = target_(a_share, b_share, fault_value, flip_mask); \
        rou_hpc_end(); \
        return result; \
    }

ROU_DEFINE_MEASURE_WRAPPER(
    rou_measure_uadd16_baseline,
    rou_target_uadd16_baseline)
ROU_DEFINE_MEASURE_WRAPPER(
    rou_measure_masked_add_baseline,
    rou_target_masked_add_baseline)
ROU_DEFINE_MEASURE_WRAPPER(
    rou_measure_skip_local_masked_operation,
    rou_target_skip_local_masked_operation)
ROU_DEFINE_MEASURE_WRAPPER(
    rou_measure_set_masked_intermediate_constant,
    rou_target_set_masked_intermediate_constant)
ROU_DEFINE_MEASURE_WRAPPER(
    rou_measure_replace_masked_intermediate_random,
    rou_target_replace_masked_intermediate_random)
ROU_DEFINE_MEASURE_WRAPPER(
    rou_measure_flip_masked_intermediate_bit,
    rou_target_flip_masked_intermediate_bit)

int PQCLEAN_KYBER768_CLEAN_roulette_set_mode(unsigned int mode) {
    switch (mode) {
    case ROU_MODE_BASELINE:
    case ROU_MODE_DATA_BASELINE:
        /* Baseline for constant/random: one scalar ADD. */
        rou_selected_target = rou_target_masked_add_baseline;
        rou_selected_measure = rou_measure_masked_add_baseline;
        break;
    case ROU_MODE_SKIP_BASELINE:
        /* Paper-specific UADD16-equivalent baseline. */
        rou_selected_target = rou_target_uadd16_baseline;
        rou_selected_measure = rou_measure_uadd16_baseline;
        break;
    case ROU_MODE_SKIP_LOCAL_OPERATION:
        rou_selected_target = rou_target_skip_local_masked_operation;
        rou_selected_measure = rou_measure_skip_local_masked_operation;
        break;
    case ROU_MODE_SET_CONSTANT:
        rou_selected_target = rou_target_set_masked_intermediate_constant;
        rou_selected_measure = rou_measure_set_masked_intermediate_constant;
        break;
    case ROU_MODE_SET_RANDOM:
        rou_selected_target = rou_target_replace_masked_intermediate_random;
        rou_selected_measure = rou_measure_replace_masked_intermediate_random;
        break;
    case ROU_MODE_FLIP_BASELINE:
    case ROU_MODE_FLIP_BIT:
        /* Both modes execute the same target; only prepared data differs. */
        rou_selected_target = rou_target_flip_masked_intermediate_bit;
        rou_selected_measure = rou_measure_flip_masked_intermediate_bit;
        break;
    default:
        return -EINVAL;
    }
    rou_runtime_mode = mode;
    return 0;
}

const char *PQCLEAN_KYBER768_CLEAN_roulette_mode_name(void) {
    switch (rou_runtime_mode) {
    case ROU_MODE_BASELINE: return "canonical-baseline";
    case ROU_MODE_DATA_BASELINE: return "data-fault-expanded-baseline";
    case ROU_MODE_SKIP_BASELINE: return "uadd16-baseline";
    case ROU_MODE_FLIP_BASELINE: return "bit-flip-data-baseline";
    case ROU_MODE_SKIP_LOCAL_OPERATION: return "skip-local-masked-operation";
    case ROU_MODE_SET_CONSTANT: return "set-masked-intermediate-constant";
    case ROU_MODE_SET_RANDOM: return "replace-masked-intermediate-random";
    case ROU_MODE_FLIP_BIT: return "flip-masked-intermediate-bit";
    default: return "invalid";
    }
}

void PQCLEAN_KYBER768_CLEAN_roulette_set_target(unsigned int target_coeff) {
    rou_target_coeff = target_coeff;
}
void PQCLEAN_KYBER768_CLEAN_roulette_set_measurement_enabled(int enabled) {
    rou_measurement_enabled = enabled != 0;
}
void PQCLEAN_KYBER768_CLEAN_roulette_set_reencrypt_active(int active) {
    rou_reencrypt_active = active != 0;
}
void PQCLEAN_KYBER768_CLEAN_roulette_set_mask_seed(uint32_t seed) {
    rou_mask_prng_state = seed != 0u ? seed : UINT32_C(0x6d2b79f5);
}
void PQCLEAN_KYBER768_CLEAN_roulette_set_fault_seed(uint32_t seed) {
    rou_fault_prng_state = seed != 0u ? seed : UINT32_C(0x726f756c);
}
void PQCLEAN_KYBER768_CLEAN_roulette_set_constant(int32_t value) {
    rou_selected_constant = value;
}
int PQCLEAN_KYBER768_CLEAN_roulette_set_flip_bit(unsigned int bit) {
    if (bit >= 16u) return -ERANGE;
    rou_selected_flip_bit = bit;
    return 0;
}
void PQCLEAN_KYBER768_CLEAN_roulette_get_audit_snapshot(
    rou_audit_snapshot *out) {
    if (out != NULL) *out = rou_audit;
}

static uint8_t rou_v_symbol(
    const uint8_t ct[KYBER_CIPHERTEXTBYTES],
    unsigned int target) {
    size_t byte_offset =
        (size_t)KYBER_POLYVECCOMPRESSEDBYTES + (size_t)(target >> 1);
    unsigned int shift = (target & 1u) * 4u;
    return (uint8_t)((ct[byte_offset] >> shift) & 0x0fu);
}

void PQCLEAN_KYBER768_CLEAN_roulette_record_compare(
    const uint8_t input_ct[KYBER_CIPHERTEXTBYTES],
    const uint8_t reencrypted_ct[KYBER_CIPHERTEXTBYTES],
    int compare_fail) {
    unsigned int target = rou_target_coeff;
    if (target >= 128u) return;
    rou_audit.input_v_symbol = rou_v_symbol(input_ct, target);
    rou_audit.reencrypted_v_symbol = rou_v_symbol(reencrypted_ct, target);
    rou_audit.target_symbol_match =
        rou_audit.input_v_symbol == rou_audit.reencrypted_v_symbol;
    rou_audit.compare_fail = compare_fail != 0;
    rou_audit.oracle_success = compare_fail == 0;
    rou_audit.compare_recorded = 1u;
}

void PQCLEAN_KYBER768_CLEAN_roulette_masked_invntt_apply(poly *v) {
    poly reference;
    int16_t share0[KYBER_N];
    int16_t share1[KYBER_N];
    unsigned int target = rou_target_coeff;
    unsigned int start;
    unsigned int len;
    unsigned int j;
    unsigned int k;
    unsigned int mismatch_count = 0u;
    int target_seen = 0;
    int extended_window_active = 0;
    const int extended_window_mode =
        rou_runtime_mode == ROU_MODE_DATA_BASELINE ||
        rou_runtime_mode == ROU_MODE_SET_CONSTANT ||
        rou_runtime_mode == ROU_MODE_SET_RANDOM ||
        rou_runtime_mode == ROU_MODE_FLIP_BASELINE ||
        rou_runtime_mode == ROU_MODE_FLIP_BIT;
    const int16_t f = 1441;

    if (!rou_reencrypt_active) {
        PQCLEAN_KYBER768_CLEAN_poly_invntt_tomont(v);
        return;
    }

    rou_reencrypt_invocations++;
    memset(&rou_audit, 0, sizeof(rou_audit));
    rou_audit.mode = rou_runtime_mode;
    rou_audit.target_coeff = target;
    rou_audit.selected_constant = rou_selected_constant;
    rou_audit.flip_bit = rou_selected_flip_bit;
    rou_audit.flip_mask = UINT32_C(1) << rou_selected_flip_bit;
    rou_audit.operation_skipped =
        rou_runtime_mode == ROU_MODE_SKIP_LOCAL_OPERATION;
    rou_audit.constant_replacement =
        rou_runtime_mode == ROU_MODE_SET_CONSTANT;
    rou_audit.random_replacement =
        rou_runtime_mode == ROU_MODE_SET_RANDOM;
    rou_audit.bit_flipped = rou_runtime_mode == ROU_MODE_FLIP_BIT;

    if (target >= 128u) {
        rou_snapshot.error_code = -ERANGE;
        PQCLEAN_KYBER768_CLEAN_poly_invntt_tomont(v);
        return;
    }

    reference = *v;
    PQCLEAN_KYBER768_CLEAN_poly_invntt_tomont(&reference);

    for (j = 0; j < KYBER_N; ++j) {
        int32_t value = rou_mod_q(v->coeffs[j]);
        int16_t random_share = rou_uniform_mod_q();
        share0[j] = random_share;
        share1[j] = (int16_t)rou_mod_q(value - (int32_t)random_share);
    }

    k = 127u;
    for (len = 2u; len <= 128u; len <<= 1) {
        for (start = 0u; start < KYBER_N; start = j + len) {
            int16_t zeta = PQCLEAN_KYBER768_CLEAN_zetas[k--];
            for (j = start; j < start + len; ++j) {
                int16_t a0 = share0[j];
                int16_t b0 = share0[j + len];
                int16_t a1 = share1[j];
                int16_t b1 = share1[j + len];

                if (len == 128u && j == target) {
                    int32_t normal_value = (int32_t)a0 + (int32_t)b0;
                    int32_t random_value = rou_random_fault_value(normal_value);
                    uint32_t flip_mask =
                        UINT32_C(1) << rou_selected_flip_bit;
                    int32_t fault_value;
                    int32_t used_value;

                    /*
                     * Data-only values are prepared before the measured target.
                     * The bit-flip target itself contains no synthetic XOR.
                     */
                    switch (rou_runtime_mode) {
                    case ROU_MODE_SET_CONSTANT:
                        fault_value = rou_selected_constant;
                        break;
                    case ROU_MODE_SET_RANDOM:
                        fault_value = random_value;
                        break;
                    case ROU_MODE_FLIP_BASELINE:
                        fault_value = normal_value;
                        break;
                    case ROU_MODE_FLIP_BIT:
                        fault_value =
                            normal_value ^ (int32_t)flip_mask;
                        break;
                    default:
                        fault_value = random_value;
                        break;
                    }

                    rou_audit.share_a_before = a0;
                    rou_audit.share_b_before = b0;
                    rou_audit.normal_intermediate = normal_value;
                    rou_audit.selected_random = random_value;

                    if (rou_measurement_enabled && rou_hpc_ready) {
                        if (extended_window_mode) {
                            /*
                             * Start immediately before the faulted/benign target.
                             * Keep counting through later butterflies, final
                             * scaling, and share recombination.
                             */
                            rou_hpc_begin();
                            extended_window_active = 1;
                            used_value = rou_selected_target(
                                a0, b0, fault_value, flip_mask);
                        } else {
                            /*
                             * Instruction skip keeps the exact local window.
                             */
                            used_value = rou_selected_measure(
                                a0, b0, fault_value, flip_mask);
                        }
                    } else {
                        used_value = rou_selected_target(
                            a0, b0, fault_value, flip_mask);
                    }

                    rou_audit.used_intermediate = used_value;
                    share0[j] =
                        PQCLEAN_KYBER768_CLEAN_barrett_reduce(
                            (int16_t)used_value);
                    target_seen = 1;
                } else {
                    share0[j] =
                        PQCLEAN_KYBER768_CLEAN_barrett_reduce(
                            (int16_t)((int32_t)a0 + b0));
                }

                share0[j + len] =
                    rou_fqmul(zeta, (int16_t)((int32_t)b0 - a0));
                share1[j] =
                    PQCLEAN_KYBER768_CLEAN_barrett_reduce(
                        (int16_t)((int32_t)a1 + b1));
                share1[j + len] =
                    rou_fqmul(zeta, (int16_t)((int32_t)b1 - a1));
            }
        }
    }

    for (j = 0; j < KYBER_N; ++j) {
        share0[j] = rou_fqmul(share0[j], f);
        share1[j] = rou_fqmul(share1[j], f);
        v->coeffs[j] =
            PQCLEAN_KYBER768_CLEAN_barrett_reduce(
                (int16_t)((int32_t)share0[j] + share1[j]));
    }

    /*
     * End before semantic audit, output tagging, ciphertext comparison, or
     * reporting. Only normal masked-INTT propagation remains in the window.
     */
    if (extended_window_active) {
        rou_hpc_end();
        extended_window_active = 0;
    }

    rou_audit.reference_coeff_mod_q = rou_mod_q(reference.coeffs[target]);
    rou_audit.observed_coeff_mod_q = rou_mod_q(v->coeffs[target]);
    rou_audit.target_changed =
        rou_audit.reference_coeff_mod_q != rou_audit.observed_coeff_mod_q;
    rou_audit.reference_output_tag = rou_poly_tag(&reference);
    rou_audit.observed_output_tag = rou_poly_tag(v);

    for (j = 0; j < KYBER_N; ++j) {
        if (j == target) continue;
        if (rou_mod_q(reference.coeffs[j]) != rou_mod_q(v->coeffs[j])) {
            mismatch_count++;
        }
    }
    rou_audit.non_target_mismatches = mismatch_count;
    rou_audit.fault_applied =
        rou_runtime_mode == ROU_MODE_SKIP_LOCAL_OPERATION ||
        rou_runtime_mode == ROU_MODE_SET_CONSTANT ||
        rou_runtime_mode == ROU_MODE_SET_RANDOM ||
        rou_runtime_mode == ROU_MODE_FLIP_BIT;

    {
        int32_t expected_value;
        switch (rou_runtime_mode) {
        case ROU_MODE_BASELINE:
        case ROU_MODE_SKIP_BASELINE:
        case ROU_MODE_FLIP_BASELINE:
        case ROU_MODE_DATA_BASELINE:
            expected_value = rou_audit.normal_intermediate;
            break;
        case ROU_MODE_SKIP_LOCAL_OPERATION:
            expected_value = rou_audit.share_a_before;
            break;
        case ROU_MODE_SET_CONSTANT:
            expected_value = rou_audit.selected_constant;
            break;
        case ROU_MODE_SET_RANDOM:
            expected_value = rou_audit.selected_random;
            break;
        case ROU_MODE_FLIP_BIT:
            expected_value =
                rou_audit.normal_intermediate ^ (int32_t)rou_audit.flip_mask;
            break;
        default:
            expected_value = INT32_MIN;
            break;
        }
        /*
         * Share-wise INTT recombination is checked coefficient-wise modulo q.
         * The ordinary and masked paths may use different signed int16
         * representatives of the same Z_q elements, so raw output-tag equality
         * is diagnostic only and must not be part of semantic validity.
         */
        rou_audit.valid =
            target_seen &&
            mismatch_count == 0u &&
            rou_audit.used_intermediate == expected_value &&
            ((rou_runtime_mode != ROU_MODE_BASELINE &&
              rou_runtime_mode != ROU_MODE_SKIP_BASELINE &&
              rou_runtime_mode != ROU_MODE_FLIP_BASELINE &&
              rou_runtime_mode != ROU_MODE_DATA_BASELINE) ||
             rou_audit.reference_coeff_mod_q ==
                 rou_audit.observed_coeff_mod_q);
    }
}
