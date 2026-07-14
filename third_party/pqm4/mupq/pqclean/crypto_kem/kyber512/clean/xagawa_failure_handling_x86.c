#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "xagawa_failure_handling_x86.h"

#include "params.h"
#include "verify.h"

#include <errno.h>
#include <linux/perf_event.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef XAGAWA_FAILURE_BUILD_MODE
#error "XAGAWA_FAILURE_BUILD_MODE must be defined at compile time"
#endif

#if XAGAWA_FAILURE_BUILD_MODE != XAGAWA_FAILURE_MODE_BASELINE && \
    XAGAWA_FAILURE_BUILD_MODE != XAGAWA_FAILURE_MODE_SKIP_CMOV
#error "invalid XAGAWA_FAILURE_BUILD_MODE"
#endif

#ifndef XAGAWA_PMU_TYPE
#define XAGAWA_PMU_TYPE 4u
#endif

#ifndef XAGAWA_LOAD_CONFIG
#define XAGAWA_LOAD_CONFIG UINT64_C(0x81d0)
#endif

#ifndef XAGAWA_STORE_CONFIG
#define XAGAWA_STORE_CONFIG UINT64_C(0x82d0)
#endif

typedef struct {
    const char *name;
    uint32_t type;
    uint64_t config;
} xagawa_event_desc;

static const xagawa_event_desc xagawa_events[
    XAGAWA_FAILURE_HPC_EVENT_COUNT] = {
    {"cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES},
    {"instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS},
    {"branches", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS},
    {"branch-misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES},
    {"retired-loads", XAGAWA_PMU_TYPE, XAGAWA_LOAD_CONFIG},
    {"retired-stores", XAGAWA_PMU_TYPE, XAGAWA_STORE_CONFIG},
};

static int xagawa_fds[XAGAWA_FAILURE_HPC_EVENT_COUNT] = {
    -1, -1, -1, -1, -1, -1
};
static uint64_t xagawa_ids[XAGAWA_FAILURE_HPC_EVENT_COUNT];
static int xagawa_hpc_ready;
static int xagawa_measurement_enabled;
static uint64_t xagawa_failure_handling_invocations;
static xagawa_failure_hpc_snapshot xagawa_snapshot;
static xagawa_failure_audit_snapshot xagawa_audit;

static long xagawa_perf_event_open(struct perf_event_attr *attr,
                                   pid_t pid,
                                   int cpu,
                                   int group_fd,
                                   unsigned long flags)
{
    return syscall(SYS_perf_event_open,
                   attr,
                   pid,
                   cpu,
                   group_fd,
                   flags);
}

static void xagawa_close_all(void)
{
    unsigned int i;

    for (i = 0; i < XAGAWA_FAILURE_HPC_EVENT_COUNT; ++i) {
        if (xagawa_fds[i] >= 0) {
            close(xagawa_fds[i]);
            xagawa_fds[i] = -1;
        }
        xagawa_ids[i] = 0;
    }

    xagawa_hpc_ready = 0;
}

int PQCLEAN_KYBER512_CLEAN_xagawa_failure_hpc_init(void)
{
    struct perf_event_attr attr;
    int leader = -1;
    unsigned int i;

    xagawa_close_all();
    memset(&xagawa_snapshot, 0, sizeof(xagawa_snapshot));

    for (i = 0; i < XAGAWA_FAILURE_HPC_EVENT_COUNT; ++i) {
        memset(&attr, 0, sizeof(attr));
        attr.size = sizeof(attr);
        attr.type = xagawa_events[i].type;
        attr.config = xagawa_events[i].config;
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

        xagawa_fds[i] = (int)xagawa_perf_event_open(
            &attr,
            0,
            -1,
            leader,
            PERF_FLAG_FD_CLOEXEC);

        if (xagawa_fds[i] < 0) {
            int saved = errno;
            xagawa_close_all();
            xagawa_snapshot.error_code = -saved;
            return -saved;
        }

        if (i == 0u) {
            leader = xagawa_fds[i];
        }

        if (ioctl(xagawa_fds[i],
                  PERF_EVENT_IOC_ID,
                  &xagawa_ids[i]) != 0) {
            int saved = errno;
            xagawa_close_all();
            xagawa_snapshot.error_code = -saved;
            return -saved;
        }
    }

    xagawa_hpc_ready = 1;
    xagawa_snapshot.error_code = 0;
    return 0;
}

void PQCLEAN_KYBER512_CLEAN_xagawa_failure_hpc_close(void)
{
    xagawa_close_all();
}

void PQCLEAN_KYBER512_CLEAN_xagawa_failure_set_measurement_enabled(
    int enabled)
{
    xagawa_measurement_enabled = enabled != 0;
}

void PQCLEAN_KYBER512_CLEAN_xagawa_failure_get_hpc_snapshot(
    xagawa_failure_hpc_snapshot *out)
{
    if (out != NULL) {
        *out = xagawa_snapshot;
    }
}

void PQCLEAN_KYBER512_CLEAN_xagawa_failure_get_audit_snapshot(
    xagawa_failure_audit_snapshot *out)
{
    if (out != NULL) {
        *out = xagawa_audit;
    }
}

int PQCLEAN_KYBER512_CLEAN_xagawa_failure_build_mode(void)
{
    return XAGAWA_FAILURE_BUILD_MODE;
}

const char *PQCLEAN_KYBER512_CLEAN_xagawa_failure_mode_name(void)
{
#if XAGAWA_FAILURE_BUILD_MODE == XAGAWA_FAILURE_MODE_BASELINE
    return "baseline";
#else
    return "skip-cmov";
#endif
}

const char *PQCLEAN_KYBER512_CLEAN_xagawa_failure_event_name(
    unsigned int index)
{
    if (index >= XAGAWA_FAILURE_HPC_EVENT_COUNT) {
        return "unknown";
    }
    return xagawa_events[index].name;
}

static inline void xagawa_compiler_barrier(void)
{
    __asm__ volatile("" ::: "memory");
}

typedef struct {
    uint64_t value;
    uint64_t id;
} xagawa_read_value;

typedef struct {
    uint64_t nr;
    uint64_t time_enabled;
    uint64_t time_running;
    xagawa_read_value values[XAGAWA_FAILURE_HPC_EVENT_COUNT];
} xagawa_group_read;

static inline void xagawa_hpc_begin_unconditional(void)
{
    xagawa_snapshot.error_code = 0;
    xagawa_compiler_barrier();

    if (ioctl(xagawa_fds[0],
              PERF_EVENT_IOC_RESET,
              PERF_IOC_FLAG_GROUP) != 0) {
        xagawa_snapshot.error_code = -errno;
    }

    if (ioctl(xagawa_fds[0],
              PERF_EVENT_IOC_ENABLE,
              PERF_IOC_FLAG_GROUP) != 0) {
        xagawa_snapshot.error_code = -errno;
    }

    xagawa_compiler_barrier();
}

static void xagawa_hpc_end_unconditional(void)
{
    xagawa_group_read data;
    ssize_t got;
    unsigned int i;
    unsigned int j;

    xagawa_compiler_barrier();

    if (ioctl(xagawa_fds[0],
              PERF_EVENT_IOC_DISABLE,
              PERF_IOC_FLAG_GROUP) != 0) {
        xagawa_snapshot.error_code = -errno;
    }

    xagawa_compiler_barrier();
    memset(&data, 0, sizeof(data));
    got = read(xagawa_fds[0], &data, sizeof(data));

    xagawa_snapshot.sequence++;
    xagawa_snapshot.failure_handling_invocations =
        xagawa_failure_handling_invocations;
    xagawa_snapshot.valid_mask = 0;
    memset(xagawa_snapshot.values,
           0,
           sizeof(xagawa_snapshot.values));

    if (got < (ssize_t)(3u * sizeof(uint64_t))) {
        xagawa_snapshot.error_code =
            (got < 0) ? -errno : -EIO;
        return;
    }

    xagawa_snapshot.time_enabled = data.time_enabled;
    xagawa_snapshot.time_running = data.time_running;

    if (data.nr > XAGAWA_FAILURE_HPC_EVENT_COUNT) {
        data.nr = XAGAWA_FAILURE_HPC_EVENT_COUNT;
    }

    for (i = 0; i < data.nr; ++i) {
        for (j = 0;
             j < XAGAWA_FAILURE_HPC_EVENT_COUNT;
             ++j) {
            if (data.values[i].id == xagawa_ids[j]) {
                xagawa_snapshot.values[j] =
                    data.values[i].value;
                xagawa_snapshot.valid_mask |=
                    (uint32_t)(1u << j);
                break;
            }
        }
    }
}

/*
 * The monitored function contains no runtime attack-mode selection.
 *
 * Baseline build:
 *     execute the original 32-byte Kyber cmov call.
 *
 * Attack build:
 *     the cmov call is absent. Verification, H(c), and KDF are not here and
 *     therefore remain unchanged in kem.c.
 *
 * No dummy call, NOP, loop, software fault flag, or replacement overwrite is
 * inserted in the attack window.
 */
static __attribute__((noinline, noclone, used))
void xagawa_failure_apply_measured(uint8_t *kr,
                                   const uint8_t *fallback_z,
                                   size_t len,
                                   uint8_t fail)
{
    xagawa_hpc_begin_unconditional();

#if XAGAWA_FAILURE_BUILD_MODE == XAGAWA_FAILURE_MODE_BASELINE
    PQCLEAN_KYBER512_CLEAN_cmov(kr, fallback_z, len, fail);
#else
    (void)kr;
    (void)fallback_z;
    (void)len;
    (void)fail;
#endif

    xagawa_hpc_end_unconditional();
}

static __attribute__((noinline, noclone))
void xagawa_failure_apply_unmeasured(uint8_t *kr,
                                     const uint8_t *fallback_z,
                                     size_t len,
                                     uint8_t fail)
{
#if XAGAWA_FAILURE_BUILD_MODE == XAGAWA_FAILURE_MODE_BASELINE
    PQCLEAN_KYBER512_CLEAN_cmov(kr, fallback_z, len, fail);
#else
    (void)kr;
    (void)fallback_z;
    (void)len;
    (void)fail;
#endif
}

void PQCLEAN_KYBER512_CLEAN_xagawa_failure_handling_apply(
    uint8_t *kr,
    const uint8_t *fallback_z,
    size_t len,
    uint8_t fail)
{
    uint8_t before[KYBER_SYMBYTES];

    xagawa_failure_handling_invocations++;

    memset(&xagawa_audit, 0, sizeof(xagawa_audit));

    /*
     * The Kyber call site always uses len == KYBER_SYMBYTES and fail in {0,1}.
     * Validation occurs while counters are disabled.
     */
    if (kr == NULL ||
        fallback_z == NULL ||
        len != (size_t)KYBER_SYMBYTES ||
        fail > 1u) {
        xagawa_snapshot.error_code = -EINVAL;
        xagawa_snapshot.fail_flag = fail;
        xagawa_snapshot.cmov_len = (uint32_t)len;
        return;
    }

    /*
     * Pre-state capture occurs before the counter enable.
     */
    memcpy(before, kr, len);

    if (xagawa_measurement_enabled && xagawa_hpc_ready) {
        xagawa_failure_apply_measured(
            kr, fallback_z, len, fail);
    } else {
        xagawa_failure_apply_unmeasured(
            kr, fallback_z, len, fail);
    }

    /*
     * Semantic checks occur only after the counter disable.
     */
    xagawa_audit.fail_flag = fail;
    xagawa_audit.cmov_len = (uint32_t)len;
    xagawa_audit.prekey_preserved =
        (uint32_t)(memcmp(kr, before, len) == 0);
    xagawa_audit.fallback_applied =
        (uint32_t)(memcmp(kr, fallback_z, len) == 0);
    xagawa_audit.valid = 1;

    xagawa_snapshot.fail_flag = fail;
    xagawa_snapshot.cmov_len = (uint32_t)len;
}
