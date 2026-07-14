#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "ravi_nnuo_x86.h"

#include <errno.h>
#include <linux/perf_event.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef NNUO_X86_BUILD_MODE
#error "NNUO_X86_BUILD_MODE must be defined at compile time"
#endif

#if NNUO_X86_BUILD_MODE != NNUO_X86_MODE_BASELINE && \
    NNUO_X86_BUILD_MODE != NNUO_X86_MODE_SKIP_INCREMENT
#error "invalid NNUO_X86_BUILD_MODE"
#endif

typedef struct {
    const char *name;
    uint32_t type;
    uint64_t config;
} nnuo_event_desc;

/*
 * The retired load/store PMU encodings are resolved by perf on the
 * installation machine. The generated values below are specific to that
 * cpu_core PMU.
 */
static const nnuo_event_desc nnuo_events[NNUO_X86_EVENT_COUNT] = {
    {"cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES},
    {"instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS},
    {"branches", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS},
    {"branch-misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES},
    {"retired-loads", 4u, UINT64_C(0x81d0)},
    {"retired-stores", 4u, UINT64_C(0x82d0)},
};

static int nnuo_fds[NNUO_X86_EVENT_COUNT] = {-1, -1, -1, -1, -1, -1};
static uint64_t nnuo_ids[NNUO_X86_EVENT_COUNT];
static int nnuo_hpc_ready;
static int nnuo_measurement_enabled;
static int nnuo_audit_enabled;
static unsigned int nnuo_target_call = L;
static uint64_t nnuo_sampling_invocations;
static nnuo_x86_hpc_snapshot nnuo_snapshot;
static nnuo_x86_audit_snapshot nnuo_audit;

static long nnuo_perf_event_open(struct perf_event_attr *attr,
                                 pid_t pid,
                                 int cpu,
                                 int group_fd,
                                 unsigned long flags)
{
    return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static void nnuo_close_all(void)
{
    unsigned int i;

    for (i = 0; i < NNUO_X86_EVENT_COUNT; ++i) {
        if (nnuo_fds[i] >= 0) {
            close(nnuo_fds[i]);
            nnuo_fds[i] = -1;
        }
        nnuo_ids[i] = 0;
    }

    nnuo_hpc_ready = 0;
}

int PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_hpc_init(void)
{
    struct perf_event_attr attr;
    int leader = -1;
    unsigned int i;

    nnuo_close_all();
    memset(&nnuo_snapshot, 0, sizeof(nnuo_snapshot));

    for (i = 0; i < NNUO_X86_EVENT_COUNT; ++i) {
        memset(&attr, 0, sizeof(attr));
        attr.size = sizeof(attr);
        attr.type = nnuo_events[i].type;
        attr.config = nnuo_events[i].config;
        attr.disabled = 1;
        attr.exclude_kernel = 1;
        attr.exclude_hv = 1;
        attr.inherit = 0;
        attr.pinned = (i == 0u) ? 1u : 0u;
        attr.read_format = PERF_FORMAT_GROUP |
                           PERF_FORMAT_ID |
                           PERF_FORMAT_TOTAL_TIME_ENABLED |
                           PERF_FORMAT_TOTAL_TIME_RUNNING;

        nnuo_fds[i] = (int)nnuo_perf_event_open(&attr,
                                                0,
                                                -1,
                                                leader,
                                                PERF_FLAG_FD_CLOEXEC);
        if (nnuo_fds[i] < 0) {
            int saved = errno;
            nnuo_close_all();
            nnuo_snapshot.error_code = -saved;
            return -saved;
        }

        if (i == 0u) {
            leader = nnuo_fds[i];
        }

        if (ioctl(nnuo_fds[i], PERF_EVENT_IOC_ID, &nnuo_ids[i]) != 0) {
            int saved = errno;
            nnuo_close_all();
            nnuo_snapshot.error_code = -saved;
            return -saved;
        }
    }

    nnuo_hpc_ready = 1;
    nnuo_snapshot.error_code = 0;
    return 0;
}

void PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_hpc_close(void)
{
    nnuo_close_all();
}

void PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_set_target(unsigned int target_call)
{
    nnuo_target_call = target_call;
}

void PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_set_measurement_enabled(int enabled)
{
    nnuo_measurement_enabled = enabled != 0;
}

void PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_set_audit_enabled(int enabled)
{
    nnuo_audit_enabled = enabled != 0;
    if (nnuo_audit_enabled) {
        memset(&nnuo_audit, 0, sizeof(nnuo_audit));
        nnuo_audit.duplicate_call = -1;
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_get_hpc_snapshot(
    nnuo_x86_hpc_snapshot *out)
{
    if (out != NULL) {
        *out = nnuo_snapshot;
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_get_audit_snapshot(
    nnuo_x86_audit_snapshot *out)
{
    if (out != NULL) {
        *out = nnuo_audit;
    }
}

int PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_build_mode(void)
{
    return NNUO_X86_BUILD_MODE;
}

const char *PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_mode_name(void)
{
#if NNUO_X86_BUILD_MODE == NNUO_X86_MODE_BASELINE
    return "baseline";
#else
    return "skip-increment";
#endif
}

const char *PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_event_name(
    unsigned int index)
{
    if (index >= NNUO_X86_EVENT_COUNT) {
        return "unknown";
    }
    return nnuo_events[index].name;
}

static inline void nnuo_compiler_barrier(void)
{
    __asm__ volatile("" ::: "memory");
}

typedef struct {
    uint64_t value;
    uint64_t id;
} nnuo_read_value;

typedef struct {
    uint64_t nr;
    uint64_t time_enabled;
    uint64_t time_running;
    nnuo_read_value values[NNUO_X86_EVENT_COUNT];
} nnuo_group_read;

static inline void nnuo_hpc_begin_unconditional(void)
{
    nnuo_compiler_barrier();

    if (ioctl(nnuo_fds[0], PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP) != 0) {
        nnuo_snapshot.error_code = -errno;
    }

    if (ioctl(nnuo_fds[0], PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP) != 0) {
        nnuo_snapshot.error_code = -errno;
    }

    nnuo_compiler_barrier();
}

static void nnuo_hpc_end_unconditional(void)
{
    nnuo_group_read data;
    ssize_t got;
    unsigned int i;
    unsigned int j;

    nnuo_compiler_barrier();

    if (ioctl(nnuo_fds[0], PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP) != 0) {
        nnuo_snapshot.error_code = -errno;
    }

    nnuo_compiler_barrier();
    memset(&data, 0, sizeof(data));
    got = read(nnuo_fds[0], &data, sizeof(data));

    nnuo_snapshot.sequence++;
    nnuo_snapshot.sampling_invocations = nnuo_sampling_invocations;
    nnuo_snapshot.target_call = nnuo_target_call;
    nnuo_snapshot.valid_mask = 0;
    memset(nnuo_snapshot.values, 0, sizeof(nnuo_snapshot.values));

    if (got < (ssize_t)(3u * sizeof(uint64_t))) {
        nnuo_snapshot.error_code = (got < 0) ? -errno : -EIO;
        return;
    }

    nnuo_snapshot.time_enabled = data.time_enabled;
    nnuo_snapshot.time_running = data.time_running;

    if (data.nr > NNUO_X86_EVENT_COUNT) {
        data.nr = NNUO_X86_EVENT_COUNT;
    }

    for (i = 0; i < data.nr; ++i) {
        for (j = 0; j < NNUO_X86_EVENT_COUNT; ++j) {
            if (data.values[i].id == nnuo_ids[j]) {
                nnuo_snapshot.values[j] = data.values[i].value;
                nnuo_snapshot.valid_mask |= (uint32_t)(1u << j);
                break;
            }
        }
    }
}

/*
 * The original semantic target is the nonce/domain-separation update:
 *
 *     nonce_state++
 *
 * The sampler itself is not changed.
 */
static __attribute__((noinline))
void nnuo_nonce_update_normal(uint16_t *nonce_state)
{
    *nonce_state = (uint16_t)(*nonce_state + 1u);
}

/*
 * Faulted target: the nonce increment is absent.
 *
 * The empty asm emits no attack instruction. Its memory operand only prevents
 * the compiler from inventing or deleting accesses around this C-level
 * no-update primitive.
 */
static __attribute__((noinline))
void nnuo_nonce_update_skip_increment(uint16_t *nonce_state)
{
    __asm__ volatile("" : "+m"(*nonce_state) : : "memory");
}

/*
 * Compile-time selection removes runtime attack dispatch from the measured
 * region.
 */
static inline __attribute__((always_inline))
void nnuo_nonce_update_target_selected(uint16_t *nonce_state)
{
#if NNUO_X86_BUILD_MODE == NNUO_X86_MODE_BASELINE
    nnuo_nonce_update_normal(nonce_state);
#else
    nnuo_nonce_update_skip_increment(nonce_state);
#endif
}

static void nnuo_prepare_outputs(polyvecl *s1,
                                 polyveck *s2,
                                 poly *outputs[NNUO_X86_TOTAL_CALLS])
{
    unsigned int call;

    for (call = 0; call < (unsigned int)L; ++call) {
        outputs[call] = &s1->vec[call];
    }

    for (call = 0; call < (unsigned int)K; ++call) {
        outputs[(unsigned int)L + call] = &s2->vec[call];
    }
}

static __attribute__((noinline))
void nnuo_sampler_one(poly *out,
                      const uint8_t seed[CRHBYTES],
                      uint16_t nonce)
{
    PQCLEAN_DILITHIUM2_CLEAN_poly_uniform_eta(out, seed, nonce);
}

/*
 * The monitored body contains only the authentic update-and-sample sequence:
 *
 *   normal prefix
 *   selected target update
 *   normal suffix
 *
 * There is no per-iteration target comparison and no runtime fault-mode
 * branch. The actual PQClean poly_uniform_eta sampler runs after every update.
 */
static __attribute__((noinline))
void nnuo_execute_measured(poly *outputs[NNUO_X86_TOTAL_CALLS],
                           const uint8_t seed[CRHBYTES],
                           unsigned int target)
{
    unsigned int call;
    uint16_t nonce_state = 0xffffu;

    /*
     * Prefix runs with counters disabled.
     */
    for (call = 0; call < target; ++call) {
        nnuo_nonce_update_normal(&nonce_state);
        nnuo_sampler_one(outputs[call], seed, nonce_state);
    }

    /*
     * The target HPC window contains only the selected nonce-update
     * primitive. Fault selection was resolved at compile time.
     */
    nnuo_hpc_begin_unconditional();
    nnuo_nonce_update_target_selected(&nonce_state);
    nnuo_hpc_end_unconditional();

    /*
     * The original PQClean sampler still runs normally with the resulting
     * nonce, but it is outside the target-update HPC window.
     */
    nnuo_sampler_one(outputs[target], seed, nonce_state);

    /*
     * Suffix continues normally from the updated or stale nonce state, with
     * counters disabled.
     */
    for (call = target + 1u; call < NNUO_X86_TOTAL_CALLS; ++call) {
        nnuo_nonce_update_normal(&nonce_state);
        nnuo_sampler_one(outputs[call], seed, nonce_state);
    }
}
static __attribute__((noinline))
void nnuo_execute_unmeasured(poly *outputs[NNUO_X86_TOTAL_CALLS],
                             const uint8_t seed[CRHBYTES],
                             unsigned int target)
{
    unsigned int call;
    uint16_t nonce_state = 0xffffu;

    for (call = 0; call < target; ++call) {
        nnuo_nonce_update_normal(&nonce_state);
        nnuo_sampler_one(outputs[call], seed, nonce_state);
    }

    nnuo_nonce_update_target_selected(&nonce_state);
    nnuo_sampler_one(outputs[target], seed, nonce_state);

    for (call = target + 1u; call < NNUO_X86_TOTAL_CALLS; ++call) {
        nnuo_nonce_update_normal(&nonce_state);
        nnuo_sampler_one(outputs[call], seed, nonce_state);
    }
}

static void nnuo_finish_audit(poly *outputs[NNUO_X86_TOTAL_CALLS],
                              unsigned int target)
{
    unsigned int call;
    poly *target_poly;

    nnuo_audit.target_call = target;
    nnuo_audit.expected_nonce_target = (uint16_t)target;
    nnuo_audit.used_nonce_target = nnuo_audit.used_nonces[target];
    nnuo_audit.nonce_progress_errors = 0;
    nnuo_audit.duplicate_call = -1;
    nnuo_audit.duplicate_output_equal = 0;

    for (call = 0; call < NNUO_X86_TOTAL_CALLS; ++call) {
        if (nnuo_audit.used_nonces[call] != (uint16_t)call) {
            nnuo_audit.nonce_progress_errors++;
        }

        if (call != target &&
            nnuo_audit.used_nonces[call] ==
                nnuo_audit.used_nonces[target] &&
            nnuo_audit.duplicate_call < 0) {
            nnuo_audit.duplicate_call = (int32_t)call;
        }
    }

    if (nnuo_audit.duplicate_call >= 0) {
        target_poly = outputs[target];
        nnuo_audit.duplicate_output_equal =
            memcmp(target_poly,
                   outputs[(unsigned int)nnuo_audit.duplicate_call],
                   sizeof(*target_poly)) == 0;
    }

    nnuo_audit.valid = 1;
}

static __attribute__((noinline))
void nnuo_execute_audited(poly *outputs[NNUO_X86_TOTAL_CALLS],
                          const uint8_t seed[CRHBYTES],
                          unsigned int target)
{
    unsigned int call;
    uint16_t nonce_state = 0xffffu;

    for (call = 0; call < target; ++call) {
        nnuo_nonce_update_normal(&nonce_state);
        nnuo_audit.used_nonces[call] = nonce_state;
        nnuo_sampler_one(outputs[call], seed, nonce_state);
    }

    nnuo_nonce_update_target_selected(&nonce_state);
    nnuo_audit.used_nonces[target] = nonce_state;
    nnuo_sampler_one(outputs[target], seed, nonce_state);

    for (call = target + 1u; call < NNUO_X86_TOTAL_CALLS; ++call) {
        nnuo_nonce_update_normal(&nonce_state);
        nnuo_audit.used_nonces[call] = nonce_state;
        nnuo_sampler_one(outputs[call], seed, nonce_state);
    }

    nnuo_finish_audit(outputs, target);
}

int PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_sample_secret_vectors(
    polyvecl *s1,
    polyveck *s2,
    const uint8_t seed[CRHBYTES])
{
    unsigned int target = nnuo_target_call;
    poly *outputs[NNUO_X86_TOTAL_CALLS];

    nnuo_sampling_invocations++;

    /*
     * Validation and all control decisions occur before counters are enabled.
     */
    if (s1 == NULL || s2 == NULL || seed == NULL) {
        nnuo_snapshot.error_code = -EINVAL;
        return -EINVAL;
    }

    if (target >= NNUO_X86_TOTAL_CALLS) {
        nnuo_snapshot.error_code = -ERANGE;
        return -ERANGE;
    }

    /*
     * Output routing is prepared before any counter is enabled. The monitored
     * loops therefore contain no s1-versus-s2 dispatch branch.
     */
    nnuo_prepare_outputs(s1, s2, outputs);

    if (nnuo_audit_enabled) {
        nnuo_execute_audited(outputs, seed, target);
        return 0;
    }

    if (nnuo_measurement_enabled && nnuo_hpc_ready) {
        nnuo_execute_measured(outputs, seed, target);
        return nnuo_snapshot.error_code;
    }

    nnuo_execute_unmeasured(outputs, seed, target);
    return 0;
}
