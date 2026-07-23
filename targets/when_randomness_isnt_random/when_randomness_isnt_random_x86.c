#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "when_randomness_isnt_random_x86.h"

#include <errno.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef WRIR_COUNTER_SET
#define WRIR_COUNTER_SET WRIR_COUNTER_INSTRUCTIONS
#endif

#ifndef WRIR_PMU_TYPE
#define WRIR_PMU_TYPE 4u
#endif

#ifndef WRIR_LOAD_CONFIG
#define WRIR_LOAD_CONFIG UINT64_C(0x81d0)
#endif

#ifndef WRIR_STORE_CONFIG
#define WRIR_STORE_CONFIG UINT64_C(0x82d0)
#endif

typedef struct {
    const char *name;
    uint32_t type;
    uint64_t config;
} event_desc;

#define CACHE_CONFIG(cache_, op_, result_) \
    ((uint64_t)(cache_) | ((uint64_t)(op_) << 8) | \
     ((uint64_t)(result_) << 16))

static const event_desc EVENTS[WRIR_HPC_EVENT_COUNT] = {
    {"cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES},
#if WRIR_COUNTER_SET == WRIR_COUNTER_INSTRUCTIONS
    {"instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS},
#elif WRIR_COUNTER_SET == WRIR_COUNTER_RETIRED_LOADS
    {"retired_loads", WRIR_PMU_TYPE, WRIR_LOAD_CONFIG},
#elif WRIR_COUNTER_SET == WRIR_COUNTER_RETIRED_STORES
    {"retired_stores", WRIR_PMU_TYPE, WRIR_STORE_CONFIG},
#elif WRIR_COUNTER_SET == WRIR_COUNTER_L1D_MISSES
    {"l1d_read_misses", PERF_TYPE_HW_CACHE,
     CACHE_CONFIG(PERF_COUNT_HW_CACHE_L1D,
                  PERF_COUNT_HW_CACHE_OP_READ,
                  PERF_COUNT_HW_CACHE_RESULT_MISS)},
#elif WRIR_COUNTER_SET == WRIR_COUNTER_LLC_MISSES
    {"llc_read_misses", PERF_TYPE_HW_CACHE,
     CACHE_CONFIG(PERF_COUNT_HW_CACHE_LL,
                  PERF_COUNT_HW_CACHE_OP_READ,
                  PERF_COUNT_HW_CACHE_RESULT_MISS)},
#elif WRIR_COUNTER_SET == WRIR_COUNTER_DTLB_MISSES
    {"dtlb_read_misses", PERF_TYPE_HW_CACHE,
     CACHE_CONFIG(PERF_COUNT_HW_CACHE_DTLB,
                  PERF_COUNT_HW_CACHE_OP_READ,
                  PERF_COUNT_HW_CACHE_RESULT_MISS)},
#elif WRIR_COUNTER_SET == WRIR_COUNTER_CACHE_REFERENCES
    {"cache_references", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES},
#elif WRIR_COUNTER_SET == WRIR_COUNTER_CACHE_MISSES
    {"cache_misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES},
#else
#error "invalid WRIR_COUNTER_SET"
#endif
};

typedef struct {
    uint64_t value;
    uint64_t id;
} read_value;

typedef struct {
    uint64_t nr;
    uint64_t time_enabled;
    uint64_t time_running;
    read_value values[WRIR_HPC_EVENT_COUNT];
} group_read;

static int fds[WRIR_HPC_EVENT_COUNT] = {-1, -1};
static uint64_t ids[WRIR_HPC_EVENT_COUNT];
static wrir_hpc_snapshot snapshot;

static long perf_event_open(
    struct perf_event_attr *attr,
    pid_t pid,
    int cpu,
    int group_fd,
    unsigned long flags)
{
    return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static void close_all(void)
{
    unsigned int i;
    for (i = 0; i < WRIR_HPC_EVENT_COUNT; ++i) {
        if (fds[i] >= 0) {
            close(fds[i]);
            fds[i] = -1;
        }
        ids[i] = 0;
    }
}

int wrir_hpc_init(void)
{
    int leader = -1;
    unsigned int i;

    close_all();
    memset(&snapshot, 0, sizeof(snapshot));

    for (i = 0; i < WRIR_HPC_EVENT_COUNT; ++i) {
        struct perf_event_attr attr;
        int fd;

        memset(&attr, 0, sizeof(attr));
        attr.size = sizeof(attr);
        attr.type = EVENTS[i].type;
        attr.config = EVENTS[i].config;
        attr.disabled = (i == 0);
        attr.exclude_kernel = 1;
        attr.exclude_hv = 1;
        attr.read_format =
            PERF_FORMAT_GROUP |
            PERF_FORMAT_ID |
            PERF_FORMAT_TOTAL_TIME_ENABLED |
            PERF_FORMAT_TOTAL_TIME_RUNNING;

        snapshot.requested_mask |= UINT32_C(1) << i;
        fd = (int)perf_event_open(
            &attr, 0, -1, i == 0 ? -1 : leader, 0);
        if (fd < 0) {
            int saved = errno;
            close_all();
            snapshot.error_code = -saved;
            return -saved;
        }
        if (ioctl(fd, PERF_EVENT_IOC_ID, &ids[i]) != 0) {
            int saved = errno;
            close(fd);
            close_all();
            snapshot.error_code = -saved;
            return -saved;
        }

        fds[i] = fd;
        snapshot.available_mask |= UINT32_C(1) << i;
        if (i == 0) {
            leader = fd;
        }
    }
    return 0;
}

void wrir_hpc_close(void)
{
    close_all();
}

const char *wrir_event_name(unsigned int index)
{
    return index < WRIR_HPC_EVENT_COUNT ? EVENTS[index].name : "invalid";
}

void wrir_get_hpc_snapshot(wrir_hpc_snapshot *out)
{
    if (out != NULL) {
        *out = snapshot;
    }
}

static inline void barrier(void)
{
    __asm__ __volatile__("" ::: "memory");
}

static int hpc_begin(void)
{
    snapshot.time_enabled = 0;
    snapshot.time_running = 0;
    snapshot.values[0] = 0;
    snapshot.values[1] = 0;
    snapshot.valid_mask = 0;
    snapshot.error_code = 0;

    barrier();
    if (ioctl(fds[0], PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP) != 0) {
        return -errno;
    }
    if (ioctl(fds[0], PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP) != 0) {
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
    if (ioctl(fds[0], PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP) != 0) {
        return -errno;
    }
    barrier();

    memset(&data, 0, sizeof(data));
    got = read(fds[0], &data, sizeof(data));
    if (got < (ssize_t)(3u * sizeof(uint64_t))) {
        return got < 0 ? -errno : -EIO;
    }

    snapshot.time_enabled = data.time_enabled;
    snapshot.time_running = data.time_running;
    if (data.nr > WRIR_HPC_EVENT_COUNT) {
        data.nr = WRIR_HPC_EVENT_COUNT;
    }

    for (i = 0; i < data.nr; ++i) {
        for (j = 0; j < WRIR_HPC_EVENT_COUNT; ++j) {
            if (data.values[i].id == ids[j]) {
                snapshot.values[j] = data.values[i].value;
                snapshot.valid_mask |= UINT32_C(1) << j;
                break;
            }
        }
    }
    return 0;
}

__attribute__((noinline, noclone))
void wrir_measure_target(const void *input, void *output)
{
    int rc = hpc_begin();
    if (rc != 0) {
        snapshot.error_code = rc;
        return;
    }

    wrir_target(input, output);

    rc = hpc_end();
    snapshot.error_code = rc;
}
