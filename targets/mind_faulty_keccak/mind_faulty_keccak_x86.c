#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "mind_faulty_keccak_x86.h"
#include "microarch_events_generated.h"

#include <errno.h>
#include <linux/perf_event.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#define MFK_VARIANT_ABORT_BASELINE 0
#define MFK_VARIANT_LOOP_ABORT 1
#define MFK_VARIANT_SKIP_BASELINE 2
#define MFK_VARIANT_SKIP_ROUND 3

#ifndef MFK_VARIANT
#define MFK_VARIANT MFK_VARIANT_ABORT_BASELINE
#endif

#ifndef MFK_ATTACK_ROUNDS
#define MFK_ATTACK_ROUNDS 8
#endif

#ifndef MFK_SKIP_ROUND
#define MFK_SKIP_ROUND 8
#endif

#ifndef MFK_COUNTER_SET
#define MFK_COUNTER_SET MFK_COUNTER_SET_STRUCTURAL_INSTRUCTIONS
#endif

#ifndef MFK_PMU_TYPE
#define MFK_PMU_TYPE 4u
#endif

#ifndef MFK_LOAD_CONFIG
#define MFK_LOAD_CONFIG UINT64_C(0x81d0)
#endif

#ifndef MFK_STORE_CONFIG
#define MFK_STORE_CONFIG UINT64_C(0x82d0)
#endif

#if MFK_VARIANT < MFK_VARIANT_ABORT_BASELINE || \
    MFK_VARIANT > MFK_VARIANT_SKIP_ROUND
#error "invalid MFK_VARIANT"
#endif

#if MFK_ATTACK_ROUNDS <= 0 || MFK_ATTACK_ROUNDS >= 24
#error "MFK_ATTACK_ROUNDS must be between 1 and 23"
#endif

#if MFK_SKIP_ROUND < 0 || MFK_SKIP_ROUND >= 24
#error "MFK_SKIP_ROUND must be between 0 and 23"
#endif

#if defined(__GNUC__) || defined(__clang__)
#define MFK_NOINLINE __attribute__((noinline, noclone, used))
#else
#define MFK_NOINLINE
#endif

typedef struct {
    const char *name;
    uint32_t type;
    uint64_t config;
    uint64_t config1;
    uint64_t config2;
    uint32_t precise_ip;
    uint32_t available;
} mfk_event_desc;

#define MFK_EVENT_GENERIC(name_, config_) \
    {name_, PERF_TYPE_HARDWARE, config_, UINT64_C(0), UINT64_C(0), 0u, 1u}

#define MFK_EVENT_RAW(name_, macro_) \
    { \
        name_, \
        MFK_EVT_##macro_##_TYPE, \
        MFK_EVT_##macro_##_CONFIG, \
        MFK_EVT_##macro_##_CONFIG1, \
        MFK_EVT_##macro_##_CONFIG2, \
        MFK_EVT_##macro_##_PRECISE_IP, \
        MFK_EVT_##macro_##_AVAILABLE \
    }

#define MFK_CACHE_CONFIG(cache, op, result) \
    ((uint64_t)(cache) | ((uint64_t)(op) << 8) | ((uint64_t)(result) << 16))

#if MFK_COUNTER_SET == MFK_COUNTER_SET_STRUCTURAL_INSTRUCTIONS
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    MFK_EVENT_GENERIC("instructions", PERF_COUNT_HW_INSTRUCTIONS),
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_STRUCTURAL_BRANCHES
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    MFK_EVENT_GENERIC("branches", PERF_COUNT_HW_BRANCH_INSTRUCTIONS),
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_STRUCTURAL_BRANCH_MISSES
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    MFK_EVENT_GENERIC("branch_misses", PERF_COUNT_HW_BRANCH_MISSES),
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_STRUCTURAL_LOADS
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"retired_loads", MFK_PMU_TYPE, MFK_LOAD_CONFIG, 0, 0, 0, 1},
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_STRUCTURAL_STORES
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"retired_stores", MFK_PMU_TYPE, MFK_STORE_CONFIG, 0, 0, 0, 1},
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_CACHE_L1D
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"l1d_read_misses", PERF_TYPE_HW_CACHE,
        MFK_CACHE_CONFIG(PERF_COUNT_HW_CACHE_L1D, PERF_COUNT_HW_CACHE_OP_READ,
                         PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_CACHE_L1I
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"l1i_read_misses", PERF_TYPE_HW_CACHE,
        MFK_CACHE_CONFIG(PERF_COUNT_HW_CACHE_L1I, PERF_COUNT_HW_CACHE_OP_READ,
                         PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_CACHE_LLC
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"llc_read_misses", PERF_TYPE_HW_CACHE,
        MFK_CACHE_CONFIG(PERF_COUNT_HW_CACHE_LL, PERF_COUNT_HW_CACHE_OP_READ,
                         PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_CACHE_DTLB
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"dtlb_read_misses", PERF_TYPE_HW_CACHE,
        MFK_CACHE_CONFIG(PERF_COUNT_HW_CACHE_DTLB, PERF_COUNT_HW_CACHE_OP_READ,
                         PERF_COUNT_HW_CACHE_RESULT_MISS), 0, 0, 0, 1},
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_CACHE_REFERENCES
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    MFK_EVENT_GENERIC("cache_references", PERF_COUNT_HW_CACHE_REFERENCES),
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_CACHE_MISSES
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    MFK_EVENT_GENERIC("cache_misses", PERF_COUNT_HW_CACHE_MISSES),
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_CACHE_L1D_REPLACEMENTS
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    MFK_EVENT_RAW("l1d_replacements", L1D_REPLACEMENTS),
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_CACHE_L2_REQUEST_MISSES
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    MFK_EVENT_RAW("l2_request_misses", L2_REQUEST_MISSES),
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_LOAD_L1_HIT
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    MFK_EVENT_RAW("load_l1_hit", LOAD_L1_HIT),
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_LOAD_L2_HIT
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    MFK_EVENT_RAW("load_l2_hit", LOAD_L2_HIT),
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_LOAD_L3_HIT
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    MFK_EVENT_RAW("load_l3_hit", LOAD_L3_HIT),
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_LOAD_L1_MISS
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    MFK_EVENT_RAW("load_l1_miss", LOAD_L1_MISS),
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_LOAD_L2_MISS
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    MFK_EVENT_RAW("load_l2_miss", LOAD_L2_MISS),
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_LOAD_L3_MISS
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    MFK_EVENT_RAW("load_l3_miss", LOAD_L3_MISS),
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_LONG_LATENCY_LOADS
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    MFK_EVENT_RAW("long_latency_loads", LONG_LATENCY_LOADS),
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_STALLS_FRONTEND
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    MFK_EVENT_GENERIC("stalled_frontend_cycles", PERF_COUNT_HW_STALLED_CYCLES_FRONTEND),
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_STALLS_BACKEND
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    MFK_EVENT_GENERIC("stalled_backend_cycles", PERF_COUNT_HW_STALLED_CYCLES_BACKEND),
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_STALLS_L1D_MISS
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    MFK_EVENT_RAW("stalls_l1d_miss", STALLS_L1D_MISS),
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_STALLS_MEM_ANY
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    MFK_EVENT_RAW("stalls_mem_any", STALLS_MEM_ANY),
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_RECOVERY_MACHINE_CLEARS
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    MFK_EVENT_RAW("machine_clears", MACHINE_CLEARS),
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_RECOVERY_MEMORY_ORDERING
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    MFK_EVENT_RAW("memory_ordering_clears", MEMORY_ORDERING_CLEARS),
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_RECOVERY_CYCLES
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    MFK_EVENT_RAW("recovery_cycles", RECOVERY_CYCLES),
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_RECOVERY_CYCLES_ANY
static const mfk_event_desc mfk_events[MFK_HPC_EVENT_COUNT] = {
    MFK_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    MFK_EVENT_RAW("recovery_cycles_any", RECOVERY_CYCLES_ANY),
};
#else
#error "invalid MFK_COUNTER_SET"
#endif

static int mfk_fds[MFK_HPC_EVENT_COUNT] = {-1, -1};
static uint64_t mfk_ids[MFK_HPC_EVENT_COUNT];
static uint32_t mfk_requested_mask;
static uint32_t mfk_available_mask;
static uint32_t mfk_open_error_mask;
static int mfk_hpc_ready;
static mfk_hpc_snapshot mfk_snapshot;

static long mfk_perf_event_open(struct perf_event_attr *attr,
                                pid_t pid,
                                int cpu,
                                int group_fd,
                                unsigned long flags) {
    return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static void mfk_close_all(void) {
    unsigned int i;
    for (i = 0; i < MFK_HPC_EVENT_COUNT; ++i) {
        if (mfk_fds[i] >= 0) {
            close(mfk_fds[i]);
            mfk_fds[i] = -1;
        }
        mfk_ids[i] = 0;
    }
    mfk_requested_mask = 0;
    mfk_available_mask = 0;
    mfk_open_error_mask = 0;
    mfk_hpc_ready = 0;
}

int mfk_hpc_init(void) {
    struct perf_event_attr attr;
    int leader = -1;
    unsigned int i;

    mfk_close_all();
    memset(&mfk_snapshot, 0, sizeof(mfk_snapshot));

    for (i = 0; i < MFK_HPC_EVENT_COUNT; ++i) {
        int saved;

        if (!mfk_events[i].available) {
            continue;
        }

        mfk_requested_mask |= (uint32_t)(1u << i);
        memset(&attr, 0, sizeof(attr));
        attr.size = sizeof(attr);
        attr.type = mfk_events[i].type;
        attr.config = mfk_events[i].config;
        attr.config1 = mfk_events[i].config1;
        attr.config2 = mfk_events[i].config2;
        attr.precise_ip = mfk_events[i].precise_ip;
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

        mfk_fds[i] = (int)mfk_perf_event_open(
            &attr, 0, -1, leader, PERF_FLAG_FD_CLOEXEC);

        if (mfk_fds[i] < 0) {
            saved = errno;
            if (i == 0u) {
                mfk_close_all();
                mfk_snapshot.error_code = -saved;
                return -saved;
            }
            mfk_open_error_mask |= (uint32_t)(1u << i);
            continue;
        }

        if (i == 0u) {
            leader = mfk_fds[i];
        }

        if (ioctl(mfk_fds[i], PERF_EVENT_IOC_ID, &mfk_ids[i]) != 0) {
            saved = errno;
            close(mfk_fds[i]);
            mfk_fds[i] = -1;
            if (i == 0u) {
                mfk_close_all();
                mfk_snapshot.error_code = -saved;
                return -saved;
            }
            mfk_open_error_mask |= (uint32_t)(1u << i);
            continue;
        }

        mfk_available_mask |= (uint32_t)(1u << i);
    }

    if ((mfk_available_mask & UINT32_C(0x1)) != UINT32_C(0x1)) {
        mfk_close_all();
        mfk_snapshot.error_code = -ENODEV;
        return -ENODEV;
    }

    mfk_snapshot.requested_mask = mfk_requested_mask;
    mfk_snapshot.available_mask = mfk_available_mask;
    mfk_snapshot.open_error_mask = mfk_open_error_mask;
    mfk_hpc_ready = 1;
    return 0;
}

void mfk_hpc_close(void) {
    mfk_close_all();
}

const char *mfk_event_name(unsigned int index) {
    return index < MFK_HPC_EVENT_COUNT ? mfk_events[index].name : "unknown";
}

void mfk_get_hpc_snapshot(mfk_hpc_snapshot *out) {
    if (out != NULL) {
        *out = mfk_snapshot;
    }
}

typedef struct {
    uint64_t value;
    uint64_t id;
} mfk_read_value;

typedef struct {
    uint64_t nr;
    uint64_t time_enabled;
    uint64_t time_running;
    mfk_read_value values[MFK_HPC_EVENT_COUNT];
} mfk_group_read;

static inline void mfk_barrier(void) {
    __asm__ volatile("" ::: "memory");
}

static inline void mfk_hpc_begin(void) {
    mfk_snapshot.error_code = 0;
    mfk_barrier();
    if (ioctl(mfk_fds[0], PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP) != 0) {
        mfk_snapshot.error_code = -errno;
    }
    if (ioctl(mfk_fds[0], PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP) != 0) {
        mfk_snapshot.error_code = -errno;
    }
    mfk_barrier();
}

static void mfk_hpc_end(void) {
    mfk_group_read data;
    ssize_t got;
    unsigned int i;
    unsigned int j;

    mfk_barrier();
    if (ioctl(mfk_fds[0], PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP) != 0) {
        mfk_snapshot.error_code = -errno;
    }
    mfk_barrier();

    memset(&data, 0, sizeof(data));
    got = read(mfk_fds[0], &data, sizeof(data));

    mfk_snapshot.sequence++;
    mfk_snapshot.requested_mask = mfk_requested_mask;
    mfk_snapshot.available_mask = mfk_available_mask;
    mfk_snapshot.open_error_mask = mfk_open_error_mask;
    mfk_snapshot.valid_mask = 0;
    memset(mfk_snapshot.values, 0, sizeof(mfk_snapshot.values));

    if (got < (ssize_t)(3u * sizeof(uint64_t))) {
        mfk_snapshot.error_code = got < 0 ? -errno : -EIO;
        return;
    }

    mfk_snapshot.time_enabled = data.time_enabled;
    mfk_snapshot.time_running = data.time_running;
    if (data.nr > MFK_HPC_EVENT_COUNT) {
        data.nr = MFK_HPC_EVENT_COUNT;
    }

    for (i = 0; i < data.nr; ++i) {
        for (j = 0; j < MFK_HPC_EVENT_COUNT; ++j) {
            if (data.values[i].id == mfk_ids[j]) {
                mfk_snapshot.values[j] = data.values[i].value;
                mfk_snapshot.valid_mask |= (uint32_t)(1u << j);
                break;
            }
        }
    }
}

static const uint64_t mfk_round_constants[24] = {
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

static const unsigned int mfk_rotation[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const unsigned int mfk_pilane[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

static inline uint64_t mfk_rol64(uint64_t x, unsigned int shift) {
    return (x << shift) | (x >> (64u - shift));
}

/* One Keccak round. Used only by the matched skip-round pair. */
MFK_NOINLINE
static void mfk_keccak_round(uint64_t state[25], unsigned int round) {
    uint64_t bc[5];
    uint64_t t;
    unsigned int i;
    unsigned int j;

    for (i = 0; i < 5; ++i) {
        bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^
                state[i + 15] ^ state[i + 20];
    }

    for (i = 0; i < 5; ++i) {
        t = bc[(i + 4) % 5] ^ mfk_rol64(bc[(i + 1) % 5], 1);
        for (j = 0; j < 25; j += 5) {
            state[j + i] ^= t;
        }
    }

    t = state[1];
    for (i = 0; i < 24; ++i) {
        j = mfk_pilane[i];
        bc[0] = state[j];
        state[j] = mfk_rol64(t, mfk_rotation[i]);
        t = bc[0];
    }

    for (j = 0; j < 25; j += 5) {
        for (i = 0; i < 5; ++i) {
            bc[i] = state[j + i];
        }
        for (i = 0; i < 5; ++i) {
            state[j + i] =
                bc[i] ^ ((~bc[(i + 1) % 5]) & bc[(i + 2) % 5]);
        }
    }

    state[0] ^= mfk_round_constants[round];
}

/*
 * Four compile-time variants are built:
 *
 * abort-baseline: original 24-round loop
 * loop-abort:     original loop bound reduced to MFK_ATTACK_ROUNDS
 * skip-baseline:  matched prefix + selected round + suffix structure
 * skip-one-round: matched prefix + suffix, with the selected round absent
 *
 * There is no runtime attack selector and no fault-assignment operation.
 */
MFK_NOINLINE
void mfk_keccak_target(uint64_t state[25]) {
#if MFK_VARIANT == MFK_VARIANT_ABORT_BASELINE || \
    MFK_VARIANT == MFK_VARIANT_LOOP_ABORT
    uint64_t bc[5];
    uint64_t t;
    unsigned int round;
    unsigned int i;
    unsigned int j;
#if MFK_VARIANT == MFK_VARIANT_LOOP_ABORT
    const unsigned int target_rounds = (unsigned int)MFK_ATTACK_ROUNDS;
#else
    const unsigned int target_rounds = 24u;
#endif

    for (round = 0; round < target_rounds; ++round) {
        for (i = 0; i < 5; ++i) {
            bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^
                    state[i + 15] ^ state[i + 20];
        }

        for (i = 0; i < 5; ++i) {
            t = bc[(i + 4) % 5] ^ mfk_rol64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5) {
                state[j + i] ^= t;
            }
        }

        t = state[1];
        for (i = 0; i < 24; ++i) {
            j = mfk_pilane[i];
            bc[0] = state[j];
            state[j] = mfk_rol64(t, mfk_rotation[i]);
            t = bc[0];
        }

        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; ++i) {
                bc[i] = state[j + i];
            }
            for (i = 0; i < 5; ++i) {
                state[j + i] =
                    bc[i] ^ ((~bc[(i + 1) % 5]) & bc[(i + 2) % 5]);
            }
        }

        state[0] ^= mfk_round_constants[round];
    }
#else
    unsigned int round;

    /* Prefix executes normally. */
    for (round = 0; round < (unsigned int)MFK_SKIP_ROUND; ++round) {
        mfk_keccak_round(state, round);
    }

#if MFK_VARIANT == MFK_VARIANT_SKIP_BASELINE
    /* The matched baseline executes the selected round. */
    mfk_keccak_round(state, (unsigned int)MFK_SKIP_ROUND);
#endif

    /* Suffix executes normally in both matched binaries. */
    for (round = (unsigned int)MFK_SKIP_ROUND + 1u; round < 24u; ++round) {
        mfk_keccak_round(state, round);
    }
#endif
}

MFK_NOINLINE
void mfk_measure_target(uint64_t state[25]) {
    if (!mfk_hpc_ready) {
        mfk_snapshot.error_code = -ENODEV;
        return;
    }
    mfk_hpc_begin();
    mfk_keccak_target(state);
    mfk_hpc_end();
}

unsigned int mfk_target_rounds(void) {
#if MFK_VARIANT == MFK_VARIANT_LOOP_ABORT
    return (unsigned int)MFK_ATTACK_ROUNDS;
#elif MFK_VARIANT == MFK_VARIANT_SKIP_ROUND
    return 23u;
#else
    return 24u;
#endif
}

int mfk_skipped_round(void) {
#if MFK_VARIANT == MFK_VARIANT_SKIP_ROUND
    return MFK_SKIP_ROUND;
#else
    return -1;
#endif
}

unsigned int mfk_abort_rounds(void) {
#if MFK_VARIANT == MFK_VARIANT_LOOP_ABORT
    return (unsigned int)MFK_ATTACK_ROUNDS;
#else
    return 0u;
#endif
}

const char *mfk_mode_name(void) {
#if MFK_VARIANT == MFK_VARIANT_ABORT_BASELINE
    return "abort-baseline";
#elif MFK_VARIANT == MFK_VARIANT_LOOP_ABORT
    return "loop-abort";
#elif MFK_VARIANT == MFK_VARIANT_SKIP_BASELINE
    return "skip-baseline";
#else
    return "skip-one-round";
#endif
}

const char *mfk_attack_family(void) {
#if MFK_VARIANT == MFK_VARIANT_ABORT_BASELINE || \
    MFK_VARIANT == MFK_VARIANT_LOOP_ABORT
    return "loop-abort";
#else
    return "skip-one-round";
#endif
}
