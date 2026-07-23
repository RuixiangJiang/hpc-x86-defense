#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "mind_faulty_keccak_x86.h"

#include <errno.h>
#include <linux/perf_event.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef MFK_COUNTER_SET
#define MFK_COUNTER_SET MFK_COUNTER_SET_INSTRUCTIONS
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

typedef struct {
    const char *name;
    uint32_t type;
    uint64_t config;
} event_desc;

#define GENERIC(name_, config_) {name_, PERF_TYPE_HARDWARE, config_}

#if MFK_COUNTER_SET == MFK_COUNTER_SET_INSTRUCTIONS
static const event_desc EVENTS[MFK_HPC_EVENT_COUNT] = {
    GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    GENERIC("instructions", PERF_COUNT_HW_INSTRUCTIONS),
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_BRANCHES
static const event_desc EVENTS[MFK_HPC_EVENT_COUNT] = {
    GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    GENERIC("branches", PERF_COUNT_HW_BRANCH_INSTRUCTIONS),
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_BRANCH_MISSES
static const event_desc EVENTS[MFK_HPC_EVENT_COUNT] = {
    GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    GENERIC("branch_misses", PERF_COUNT_HW_BRANCH_MISSES),
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_LOADS
static const event_desc EVENTS[MFK_HPC_EVENT_COUNT] = {
    GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"retired_loads", MFK_PMU_TYPE, MFK_LOAD_CONFIG},
};
#elif MFK_COUNTER_SET == MFK_COUNTER_SET_STORES
static const event_desc EVENTS[MFK_HPC_EVENT_COUNT] = {
    GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    {"retired_stores", MFK_PMU_TYPE, MFK_STORE_CONFIG},
};
#else
#error "invalid MFK_COUNTER_SET"
#endif

typedef struct {
    int leader_fd;
    int fds[MFK_HPC_EVENT_COUNT];
    uint64_t ids[MFK_HPC_EVENT_COUNT];
    uint32_t requested_mask;
    uint32_t available_mask;
    uint32_t open_error_mask;
} perf_group;

typedef struct {
    uint64_t value;
    uint64_t id;
} read_value;

typedef struct {
    uint64_t nr;
    uint64_t time_enabled;
    uint64_t time_running;
    read_value values[MFK_HPC_EVENT_COUNT];
} group_read;

static perf_group GROUP = {.leader_fd = -1, .fds = {-1, -1}};
static mfk_hpc_snapshot SNAPSHOT;

static long perf_event_open(
    struct perf_event_attr *attr,
    pid_t pid,
    int cpu,
    int group_fd,
    unsigned long flags)
{
    return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static void close_group(void)
{
    unsigned int i;
    for (i = 0; i < MFK_HPC_EVENT_COUNT; ++i) {
        if (GROUP.fds[i] >= 0) {
            close(GROUP.fds[i]);
            GROUP.fds[i] = -1;
        }
        GROUP.ids[i] = 0;
    }
    GROUP.leader_fd = -1;
    GROUP.requested_mask = 0;
    GROUP.available_mask = 0;
    GROUP.open_error_mask = 0;
}

int mfk_hpc_init(void)
{
    unsigned int i;
    close_group();
    memset(&SNAPSHOT, 0, sizeof(SNAPSHOT));

    for (i = 0; i < MFK_HPC_EVENT_COUNT; ++i) {
        struct perf_event_attr attr;
        int fd;
        uint64_t id = 0;

        memset(&attr, 0, sizeof(attr));
        attr.size = sizeof(attr);
        attr.type = EVENTS[i].type;
        attr.config = EVENTS[i].config;
        attr.disabled = (i == 0);
        attr.exclude_kernel = 1;
        attr.exclude_hv = 1;
        attr.read_format =
            PERF_FORMAT_GROUP |
            PERF_FORMAT_TOTAL_TIME_ENABLED |
            PERF_FORMAT_TOTAL_TIME_RUNNING |
            PERF_FORMAT_ID;

        GROUP.requested_mask |= UINT32_C(1) << i;
        fd = (int)perf_event_open(
            &attr,
            0,
            -1,
            i == 0 ? -1 : GROUP.leader_fd,
            0);
        if (fd < 0) {
            GROUP.open_error_mask |= UINT32_C(1) << i;
            close_group();
            return -errno;
        }
        if (ioctl(fd, PERF_EVENT_IOC_ID, &id) != 0) {
            int saved = errno;
            close(fd);
            close_group();
            return -saved;
        }
        GROUP.fds[i] = fd;
        GROUP.ids[i] = id;
        GROUP.available_mask |= UINT32_C(1) << i;
        if (i == 0) {
            GROUP.leader_fd = fd;
        }
    }
    return 0;
}

void mfk_hpc_close(void)
{
    close_group();
}

const char *mfk_event_name(unsigned int index)
{
    return index < MFK_HPC_EVENT_COUNT ? EVENTS[index].name : "invalid";
}

void mfk_get_hpc_snapshot(mfk_hpc_snapshot *out)
{
    if (out != NULL) {
        *out = SNAPSHOT;
    }
}

static inline void barrier(void)
{
    __asm__ __volatile__("" ::: "memory");
}

static int hpc_begin(void)
{
    memset(&SNAPSHOT, 0, sizeof(SNAPSHOT));
    SNAPSHOT.requested_mask = GROUP.requested_mask;
    SNAPSHOT.available_mask = GROUP.available_mask;
    SNAPSHOT.open_error_mask = GROUP.open_error_mask;

    barrier();
    if (ioctl(GROUP.leader_fd, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP) != 0) {
        return -errno;
    }
    if (ioctl(GROUP.leader_fd, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP) != 0) {
        return -errno;
    }
    barrier();
    return 0;
}

static int hpc_end(void)
{
    group_read data;
    ssize_t got;
    unsigned int i;
    unsigned int j;

    barrier();
    if (ioctl(GROUP.leader_fd, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP) != 0) {
        return -errno;
    }
    barrier();

    memset(&data, 0, sizeof(data));
    got = read(GROUP.leader_fd, &data, sizeof(data));
    if (got < (ssize_t)(3u * sizeof(uint64_t))) {
        return got < 0 ? -errno : -EIO;
    }

    SNAPSHOT.sequence++;
    SNAPSHOT.time_enabled = data.time_enabled;
    SNAPSHOT.time_running = data.time_running;
    if (data.nr > MFK_HPC_EVENT_COUNT) {
        data.nr = MFK_HPC_EVENT_COUNT;
    }
    for (i = 0; i < data.nr; ++i) {
        for (j = 0; j < MFK_HPC_EVENT_COUNT; ++j) {
            if (data.values[i].id == GROUP.ids[j]) {
                SNAPSHOT.values[j] = data.values[i].value;
                SNAPSHOT.valid_mask |= UINT32_C(1) << j;
                break;
            }
        }
    }
    return 0;
}

static const uint64_t RC[24] = {
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

static const unsigned int ROT[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const unsigned int PILANE[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

static inline uint64_t rol64(uint64_t x, unsigned int shift)
{
    return (x << shift) | (x >> (64u - shift));
}

__attribute__((noinline, noclone, used))
void mfk_keccak_round(uint64_t state[25], unsigned int round)
{
    uint64_t bc[5];
    uint64_t t;
    unsigned int i;
    unsigned int j;

    for (i = 0; i < 5; ++i) {
        bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^
                state[i + 15] ^ state[i + 20];
    }
    for (i = 0; i < 5; ++i) {
        t = bc[(i + 4) % 5] ^ rol64(bc[(i + 1) % 5], 1);
        for (j = 0; j < 25; j += 5) {
            state[j + i] ^= t;
        }
    }
    t = state[1];
    for (i = 0; i < 24; ++i) {
        j = PILANE[i];
        bc[0] = state[j];
        state[j] = rol64(t, ROT[i]);
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
    state[0] ^= RC[round];
}

void mfk_measure_target(uint64_t state[25])
{
    int rc = hpc_begin();
    if (rc != 0) {
        SNAPSHOT.error_code = rc;
        return;
    }
    mfk_keccak_target(state);
    SNAPSHOT.error_code = hpc_end();
}
