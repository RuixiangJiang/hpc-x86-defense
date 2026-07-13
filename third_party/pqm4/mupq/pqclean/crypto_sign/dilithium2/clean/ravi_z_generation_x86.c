#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "ravi_z_generation_x86.h"

#include <errno.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef RAVI_Z_BUILD_MODE
#error "RAVI_Z_BUILD_MODE must be defined at compile time"
#endif

#if RAVI_Z_BUILD_MODE < RAVI_Z_MODE_BASELINE || \
    RAVI_Z_BUILD_MODE > RAVI_Z_MODE_SKIP_STORE
#error "invalid RAVI_Z_BUILD_MODE"
#endif

typedef struct {
    const char *name;
    uint32_t type;
    uint64_t config;
} ravi_event_desc;

/*
 * The model-specific events below are resolved by perf on this machine.
 * They count the retired memory operations that differ among the Ravi
 * baseline, skip-y, skip-cs1, and skip-store target primitives.
 *
 * MEM_INST_RETIRED.ALL_LOADS:  type=4, config=0x81d0
 * MEM_INST_RETIRED.ALL_STORES: type=4, config=0x82d0
 */
static const ravi_event_desc ravi_events[RAVI_Z_HPC_EVENT_COUNT] = {
    {"cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES},
    {"instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS},
    {"branches", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS},
    {"branch-misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES},
    {"retired-loads", 4u, UINT64_C(0x81d0)},
    {"retired-stores", 4u, UINT64_C(0x82d0)},
};

static int ravi_fds[RAVI_Z_HPC_EVENT_COUNT] = {-1, -1, -1, -1, -1, -1};
static uint64_t ravi_ids[RAVI_Z_HPC_EVENT_COUNT];
static int ravi_hpc_ready;
static int ravi_measurement_enabled;
static int ravi_audit_enabled;
static unsigned int ravi_target_vec;
static unsigned int ravi_target_coeff;
static uint64_t ravi_generation_invocations;
static ravi_z_hpc_snapshot ravi_snapshot;
static ravi_z_audit_snapshot ravi_audit;

static long ravi_perf_event_open(struct perf_event_attr *attr,
                                 pid_t pid,
                                 int cpu,
                                 int group_fd,
                                 unsigned long flags)
{
    return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static void ravi_close_all(void)
{
    unsigned int i;

    for (i = 0; i < RAVI_Z_HPC_EVENT_COUNT; ++i) {
        if (ravi_fds[i] >= 0) {
            close(ravi_fds[i]);
            ravi_fds[i] = -1;
        }
        ravi_ids[i] = 0;
    }

    ravi_hpc_ready = 0;
}

int PQCLEAN_DILITHIUM2_CLEAN_ravi_z_hpc_init(void)
{
    struct perf_event_attr attr;
    int leader = -1;
    unsigned int i;

    ravi_close_all();
    memset(&ravi_snapshot, 0, sizeof(ravi_snapshot));

    for (i = 0; i < RAVI_Z_HPC_EVENT_COUNT; ++i) {
        memset(&attr, 0, sizeof(attr));
        attr.size = sizeof(attr);
        attr.type = ravi_events[i].type;
        attr.config = ravi_events[i].config;
        attr.disabled = 1;
        attr.exclude_kernel = 1;
        attr.exclude_hv = 1;
        attr.inherit = 0;
        attr.pinned = (i == 0u) ? 1u : 0u;
        attr.read_format = PERF_FORMAT_GROUP |
                           PERF_FORMAT_ID |
                           PERF_FORMAT_TOTAL_TIME_ENABLED |
                           PERF_FORMAT_TOTAL_TIME_RUNNING;

        ravi_fds[i] = (int)ravi_perf_event_open(&attr,
                                                0,
                                                -1,
                                                leader,
                                                PERF_FLAG_FD_CLOEXEC);
        if (ravi_fds[i] < 0) {
            int saved = errno;
            ravi_close_all();
            ravi_snapshot.error_code = -saved;
            return -saved;
        }

        if (i == 0u) {
            leader = ravi_fds[i];
        }

        if (ioctl(ravi_fds[i], PERF_EVENT_IOC_ID, &ravi_ids[i]) != 0) {
            int saved = errno;
            ravi_close_all();
            ravi_snapshot.error_code = -saved;
            return -saved;
        }
    }

    ravi_hpc_ready = 1;
    ravi_snapshot.error_code = 0;
    return 0;
}

void PQCLEAN_DILITHIUM2_CLEAN_ravi_z_hpc_close(void)
{
    ravi_close_all();
}

void PQCLEAN_DILITHIUM2_CLEAN_ravi_z_set_target(unsigned int vec,
                                                 unsigned int coeff)
{
    ravi_target_vec = vec;
    ravi_target_coeff = coeff;
}

void PQCLEAN_DILITHIUM2_CLEAN_ravi_z_set_measurement_enabled(int enabled)
{
    ravi_measurement_enabled = enabled != 0;
}

void PQCLEAN_DILITHIUM2_CLEAN_ravi_z_set_audit_enabled(int enabled)
{
    ravi_audit_enabled = enabled != 0;
    if (ravi_audit_enabled) {
        memset(&ravi_audit, 0, sizeof(ravi_audit));
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_ravi_z_get_hpc_snapshot(
    ravi_z_hpc_snapshot *out)
{
    if (out != NULL) {
        *out = ravi_snapshot;
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_ravi_z_get_audit_snapshot(
    ravi_z_audit_snapshot *out)
{
    if (out != NULL) {
        *out = ravi_audit;
    }
}

int PQCLEAN_DILITHIUM2_CLEAN_ravi_z_build_mode(void)
{
    return RAVI_Z_BUILD_MODE;
}

const char *PQCLEAN_DILITHIUM2_CLEAN_ravi_z_mode_name(void)
{
#if RAVI_Z_BUILD_MODE == RAVI_Z_MODE_BASELINE
    return "baseline";
#elif RAVI_Z_BUILD_MODE == RAVI_Z_MODE_SKIP_Y
    return "skip-y";
#elif RAVI_Z_BUILD_MODE == RAVI_Z_MODE_SKIP_CS1
    return "skip-cs1";
#else
    return "skip-store";
#endif
}

const char *PQCLEAN_DILITHIUM2_CLEAN_ravi_z_event_name(unsigned int index)
{
    if (index >= RAVI_Z_HPC_EVENT_COUNT) {
        return "unknown";
    }
    return ravi_events[index].name;
}

static inline void ravi_compiler_barrier(void)
{
    __asm__ volatile("" ::: "memory");
}

typedef struct {
    uint64_t value;
    uint64_t id;
} ravi_read_value;

typedef struct {
    uint64_t nr;
    uint64_t time_enabled;
    uint64_t time_running;
    ravi_read_value values[RAVI_Z_HPC_EVENT_COUNT];
} ravi_group_read;

static inline void ravi_hpc_begin_unconditional(void)
{
    ravi_compiler_barrier();

    if (ioctl(ravi_fds[0], PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP) != 0) {
        ravi_snapshot.error_code = -errno;
    }

    if (ioctl(ravi_fds[0], PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP) != 0) {
        ravi_snapshot.error_code = -errno;
    }

    ravi_compiler_barrier();
}

static void ravi_hpc_end_unconditional(void)
{
    ravi_group_read data;
    ssize_t got;
    unsigned int i;
    unsigned int j;

    ravi_compiler_barrier();

    if (ioctl(ravi_fds[0], PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP) != 0) {
        ravi_snapshot.error_code = -errno;
    }

    ravi_compiler_barrier();
    memset(&data, 0, sizeof(data));
    got = read(ravi_fds[0], &data, sizeof(data));

    ravi_snapshot.sequence++;
    ravi_snapshot.generation_invocations = ravi_generation_invocations;
    ravi_snapshot.target_vec = ravi_target_vec;
    ravi_snapshot.target_coeff = ravi_target_coeff;
    ravi_snapshot.valid_mask = 0;
    memset(ravi_snapshot.values, 0, sizeof(ravi_snapshot.values));

    if (got < (ssize_t)(3u * sizeof(uint64_t))) {
        ravi_snapshot.error_code = (got < 0) ? -errno : -EIO;
        return;
    }

    ravi_snapshot.time_enabled = data.time_enabled;
    ravi_snapshot.time_running = data.time_running;

    if (data.nr > RAVI_Z_HPC_EVENT_COUNT) {
        data.nr = RAVI_Z_HPC_EVENT_COUNT;
    }

    for (i = 0; i < data.nr; ++i) {
        for (j = 0; j < RAVI_Z_HPC_EVENT_COUNT; ++j) {
            if (data.values[i].id == ravi_ids[j]) {
                ravi_snapshot.values[j] = data.values[i].value;
                ravi_snapshot.valid_mask |= (uint32_t)(1u << j);
                break;
            }
        }
    }
}

static inline __attribute__((always_inline))
void ravi_z_one_normal(int32_t *z_coeff, const int32_t *y_coeff)
{
    int32_t cs1_value = *z_coeff;
    int32_t y_value = *y_coeff;
    *z_coeff = cs1_value + y_value;
}

/*
 * Baseline target:
 *     z[target] = cs1[target] + y[target]
 */
static __attribute__((noinline))
void ravi_z_target_baseline(int32_t *z_coeff, const int32_t *y_coeff)
{
    int32_t cs1_value = *z_coeff;
    int32_t y_value = *y_coeff;
    *z_coeff = cs1_value + y_value;
}

/*
 * Ravi skip-y:
 *     released z[target] contains only cs1[target].
 *
 * The same-value store is kept intentionally. This distinguishes the omitted
 * y contribution from the independent skipped-store fault.
 */
static __attribute__((noinline))
void ravi_z_target_skip_y(int32_t *z_coeff, const int32_t *y_coeff)
{
    volatile int32_t *volatile_z = (volatile int32_t *)z_coeff;
    int32_t cs1_value;

    (void)y_coeff;
    cs1_value = *volatile_z;
    *volatile_z = cs1_value;
}

/*
 * Ravi skip-cs1:
 *     released z[target] contains only y[target].
 */
static __attribute__((noinline))
void ravi_z_target_skip_cs1(int32_t *z_coeff, const int32_t *y_coeff)
{
    int32_t y_value = *y_coeff;
    *z_coeff = y_value;
}

/*
 * Ravi skip-store:
 *     cs1[target] + y[target] is computed, but the result is not stored.
 */
static __attribute__((noinline))
void ravi_z_target_skip_store(int32_t *z_coeff, const int32_t *y_coeff)
{
    int32_t cs1_value = *z_coeff;
    int32_t y_value = *y_coeff;
    int32_t result = cs1_value + y_value;

    __asm__ volatile("" : : "r"(result) : "memory");
}

static inline __attribute__((always_inline))
void ravi_z_target_selected(int32_t *z_coeff, const int32_t *y_coeff)
{
#if RAVI_Z_BUILD_MODE == RAVI_Z_MODE_BASELINE
    ravi_z_target_baseline(z_coeff, y_coeff);
#elif RAVI_Z_BUILD_MODE == RAVI_Z_MODE_SKIP_Y
    ravi_z_target_skip_y(z_coeff, y_coeff);
#elif RAVI_Z_BUILD_MODE == RAVI_Z_MODE_SKIP_CS1
    ravi_z_target_skip_cs1(z_coeff, y_coeff);
#else
    ravi_z_target_skip_store(z_coeff, y_coeff);
#endif
}

/*
 * Prefix-target-suffix execution.
 *
 * There is no "if this is the target coefficient" branch inside the normal
 * coefficient loops. Fault selection is resolved at compile time, so no
 * runtime fault-mode branch exists in the measured region.
 */
#define RAVI_Z_EXECUTE_BODY(z_ptr, y_ptr, target_v, target_c)               \
    do {                                                                    \
        unsigned int ravi_v;                                                \
        unsigned int ravi_c;                                                \
        for (ravi_v = 0; ravi_v < (target_v); ++ravi_v) {                   \
            for (ravi_c = 0; ravi_c < (unsigned int)N; ++ravi_c) {          \
                ravi_z_one_normal(&(z_ptr)->vec[ravi_v].coeffs[ravi_c],     \
                                  &(y_ptr)->vec[ravi_v].coeffs[ravi_c]);     \
            }                                                               \
        }                                                                   \
        for (ravi_c = 0; ravi_c < (target_c); ++ravi_c) {                   \
            ravi_z_one_normal(&(z_ptr)->vec[(target_v)].coeffs[ravi_c],     \
                              &(y_ptr)->vec[(target_v)].coeffs[ravi_c]);     \
        }                                                                   \
        ravi_z_target_selected(                                             \
            &(z_ptr)->vec[(target_v)].coeffs[(target_c)],                   \
            &(y_ptr)->vec[(target_v)].coeffs[(target_c)]);                  \
        for (ravi_c = (target_c) + 1u; ravi_c < (unsigned int)N; ++ravi_c) {\
            ravi_z_one_normal(&(z_ptr)->vec[(target_v)].coeffs[ravi_c],     \
                              &(y_ptr)->vec[(target_v)].coeffs[ravi_c]);     \
        }                                                                   \
        for (ravi_v = (target_v) + 1u; ravi_v < (unsigned int)L; ++ravi_v) {\
            for (ravi_c = 0; ravi_c < (unsigned int)N; ++ravi_c) {          \
                ravi_z_one_normal(&(z_ptr)->vec[ravi_v].coeffs[ravi_c],     \
                                  &(y_ptr)->vec[ravi_v].coeffs[ravi_c]);     \
            }                                                               \
        }                                                                   \
    } while (0)

static __attribute__((noinline))
void ravi_z_apply_measured(polyvecl *z,
                           const polyvecl *y,
                           unsigned int target_v,
                           unsigned int target_c)
{
    /*
     * Counter setup and fault-mode selection have already completed.
     * The enabled interval contains only prefix-target-suffix z generation.
     */
    ravi_hpc_begin_unconditional();
    RAVI_Z_EXECUTE_BODY(z, y, target_v, target_c);
    ravi_hpc_end_unconditional();
}

static __attribute__((noinline))
void ravi_z_apply_unmeasured(polyvecl *z,
                             const polyvecl *y,
                             unsigned int target_v,
                             unsigned int target_c)
{
    RAVI_Z_EXECUTE_BODY(z, y, target_v, target_c);
}

static __attribute__((noinline))
void ravi_z_apply_audited(polyvecl *z,
                          const polyvecl *y,
                          unsigned int target_v,
                          unsigned int target_c)
{
    ravi_audit.cs1_before = z->vec[target_v].coeffs[target_c];
    ravi_audit.y_value = y->vec[target_v].coeffs[target_c];
    ravi_audit.target_vec = target_v;
    ravi_audit.target_coeff = target_c;

    /*
     * Audit runs only while measurement is disabled. These extra accesses are
     * never included in an HPC sample.
     */
    RAVI_Z_EXECUTE_BODY(z, y, target_v, target_c);

    ravi_audit.z_after = z->vec[target_v].coeffs[target_c];
    ravi_audit.valid = 1;
}

void PQCLEAN_DILITHIUM2_CLEAN_ravi_z_generation_apply(polyvecl *z,
                                                       const polyvecl *y)
{
    unsigned int target_v = ravi_target_vec;
    unsigned int target_c = ravi_target_coeff;

    ravi_generation_invocations++;

    /*
     * All control decisions occur before counters are enabled.
     */
    if (target_v >= (unsigned int)L || target_c >= (unsigned int)N) {
        PQCLEAN_DILITHIUM2_CLEAN_polyvecl_add(z, z, y);
        ravi_snapshot.error_code = -ERANGE;
        return;
    }

    if (ravi_audit_enabled) {
        ravi_z_apply_audited(z, y, target_v, target_c);
        return;
    }

    if (ravi_measurement_enabled && ravi_hpc_ready) {
        ravi_z_apply_measured(z, y, target_v, target_c);
        return;
    }

    ravi_z_apply_unmeasured(z, y, target_v, target_c);
}
