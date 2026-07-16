#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "fiddling_twiddle_x86.h"

#include "ntt.h"
#include "params.h"
#include "reduce.h"

#include <errno.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef FIDDLE_TWIDDLE_PMU_TYPE
#define FIDDLE_TWIDDLE_PMU_TYPE 4u
#endif

#ifndef FIDDLE_TWIDDLE_LOAD_CONFIG
#define FIDDLE_TWIDDLE_LOAD_CONFIG UINT64_C(0x81d0)
#endif

#ifndef FIDDLE_TWIDDLE_STORE_CONFIG
#define FIDDLE_TWIDDLE_STORE_CONFIG UINT64_C(0x82d0)
#endif

#if defined(__GNUC__) || defined(__clang__)
#define FIDDLE_NOINLINE __attribute__((noinline, noclone, used))
#else
#define FIDDLE_NOINLINE
#endif

typedef struct {
    const char *name;
    uint32_t type;
    uint64_t config;
} fiddle_event_desc;

static const fiddle_event_desc fiddle_events[
    FIDDLE_TWIDDLE_HPC_EVENT_COUNT] = {
    {"cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES},
    {"instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS},
    {"branches", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS},
    {"branch_misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES},
    {"retired_loads", FIDDLE_TWIDDLE_PMU_TYPE, FIDDLE_TWIDDLE_LOAD_CONFIG},
    {"retired_stores", FIDDLE_TWIDDLE_PMU_TYPE, FIDDLE_TWIDDLE_STORE_CONFIG},
};

static int fiddle_fds[FIDDLE_TWIDDLE_HPC_EVENT_COUNT] = {
    -1, -1, -1, -1, -1, -1
};
static uint64_t fiddle_ids[FIDDLE_TWIDDLE_HPC_EVENT_COUNT];

static int fiddle_hpc_ready;
static int fiddle_measurement_enabled;

static unsigned int fiddle_family = FIDDLE_FAMILY_LOADED_VALUE;
static unsigned int fiddle_mode = FIDDLE_MODE_BASELINE;
static unsigned int fiddle_target_vec;
static unsigned int fiddle_target_twiddle_index = 8u;
static unsigned int fiddle_pointer_offset = 64u;
static uint64_t fiddle_signing_invocations;

static fiddle_twiddle_hpc_snapshot fiddle_snapshot;
static fiddle_twiddle_audit_snapshot fiddle_audit;

/*
 * Existing loaded-value fault model:
 * skipping the selected load leaves this stale zero in the destination value.
 * It is read before the PMU window and passed in a register.
 */
static volatile int32_t fiddle_stale_twiddle_zero;

typedef void (*fiddle_group_runner)(
    int32_t *a,
    unsigned int len,
    const int32_t *correct_pointer,
    const int32_t *wrong_pointer,
    int32_t stale_twiddle);

static fiddle_group_runner fiddle_selected_measured_runner;
static fiddle_group_runner fiddle_selected_plain_runner;

static long fiddle_perf_event_open(
    struct perf_event_attr *attr,
    pid_t pid,
    int cpu,
    int group_fd,
    unsigned long flags)
{
    return syscall(
        SYS_perf_event_open,
        attr,
        pid,
        cpu,
        group_fd,
        flags);
}

static void fiddle_close_all(void)
{
    unsigned int i;

    for (i = 0; i < FIDDLE_TWIDDLE_HPC_EVENT_COUNT; ++i) {
        if (fiddle_fds[i] >= 0) {
            close(fiddle_fds[i]);
            fiddle_fds[i] = -1;
        }
        fiddle_ids[i] = 0;
    }

    fiddle_hpc_ready = 0;
}

int PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_hpc_init(void)
{
    struct perf_event_attr attr;
    int leader = -1;
    unsigned int i;

    fiddle_close_all();
    memset(&fiddle_snapshot, 0, sizeof(fiddle_snapshot));

    for (i = 0; i < FIDDLE_TWIDDLE_HPC_EVENT_COUNT; ++i) {
        memset(&attr, 0, sizeof(attr));
        attr.size = sizeof(attr);
        attr.type = fiddle_events[i].type;
        attr.config = fiddle_events[i].config;
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

        fiddle_fds[i] = (int)fiddle_perf_event_open(
            &attr,
            0,
            -1,
            leader,
            PERF_FLAG_FD_CLOEXEC);

        if (fiddle_fds[i] < 0) {
            int saved = errno;
            fiddle_close_all();
            fiddle_snapshot.error_code = -saved;
            return -saved;
        }

        if (i == 0u) {
            leader = fiddle_fds[i];
        }

        if (ioctl(
                fiddle_fds[i],
                PERF_EVENT_IOC_ID,
                &fiddle_ids[i]) != 0) {
            int saved = errno;
            fiddle_close_all();
            fiddle_snapshot.error_code = -saved;
            return -saved;
        }
    }

    fiddle_hpc_ready = 1;
    fiddle_snapshot.error_code = 0;
    return 0;
}

void PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_hpc_close(void)
{
    fiddle_close_all();
}

void PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_set_measurement_enabled(
    int enabled)
{
    fiddle_measurement_enabled = enabled != 0;
}

void PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_get_hpc_snapshot(
    fiddle_twiddle_hpc_snapshot *out)
{
    if (out != NULL) {
        *out = fiddle_snapshot;
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_get_audit_snapshot(
    fiddle_twiddle_audit_snapshot *out)
{
    if (out != NULL) {
        *out = fiddle_audit;
    }
}

const char *PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_event_name(
    unsigned int index)
{
    if (index >= FIDDLE_TWIDDLE_HPC_EVENT_COUNT) {
        return "unknown";
    }
    return fiddle_events[index].name;
}

const char *PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_family_name(void)
{
    return fiddle_family == FIDDLE_FAMILY_POINTER
        ? "corrupt-twiddle-pointer"
        : "corrupt-loaded-twiddle-value";
}

const char *PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_mode_name(void)
{
    return fiddle_mode == FIDDLE_MODE_ATTACK ? "attack" : "baseline";
}

static inline void fiddle_compiler_barrier(void)
{
    __asm__ volatile("" ::: "memory");
}

typedef struct {
    uint64_t value;
    uint64_t id;
} fiddle_read_value;

typedef struct {
    uint64_t nr;
    uint64_t time_enabled;
    uint64_t time_running;
    fiddle_read_value values[FIDDLE_TWIDDLE_HPC_EVENT_COUNT];
} fiddle_group_read;

static inline void fiddle_hpc_begin_unconditional(void)
{
    fiddle_snapshot.error_code = 0;
    fiddle_compiler_barrier();

    if (ioctl(
            fiddle_fds[0],
            PERF_EVENT_IOC_RESET,
            PERF_IOC_FLAG_GROUP) != 0) {
        fiddle_snapshot.error_code = -errno;
    }

    if (ioctl(
            fiddle_fds[0],
            PERF_EVENT_IOC_ENABLE,
            PERF_IOC_FLAG_GROUP) != 0) {
        fiddle_snapshot.error_code = -errno;
    }

    fiddle_compiler_barrier();
}

static void fiddle_hpc_end_unconditional(void)
{
    fiddle_group_read data;
    ssize_t got;
    unsigned int i;
    unsigned int j;

    fiddle_compiler_barrier();

    if (ioctl(
            fiddle_fds[0],
            PERF_EVENT_IOC_DISABLE,
            PERF_IOC_FLAG_GROUP) != 0) {
        fiddle_snapshot.error_code = -errno;
    }

    fiddle_compiler_barrier();
    memset(&data, 0, sizeof(data));
    got = read(fiddle_fds[0], &data, sizeof(data));

    fiddle_snapshot.sequence++;
    fiddle_snapshot.signing_invocations = fiddle_signing_invocations;
    fiddle_snapshot.target_vec = fiddle_target_vec;
    fiddle_snapshot.target_twiddle_index =
        fiddle_target_twiddle_index;
    fiddle_snapshot.used_twiddle_index =
        fiddle_audit.used_twiddle_index;
    fiddle_snapshot.valid_mask = 0;
    memset(
        fiddle_snapshot.values,
        0,
        sizeof(fiddle_snapshot.values));

    if (got < (ssize_t)(3u * sizeof(uint64_t))) {
        fiddle_snapshot.error_code =
            (got < 0) ? -errno : -EIO;
        return;
    }

    fiddle_snapshot.time_enabled = data.time_enabled;
    fiddle_snapshot.time_running = data.time_running;

    if (data.nr > FIDDLE_TWIDDLE_HPC_EVENT_COUNT) {
        data.nr = FIDDLE_TWIDDLE_HPC_EVENT_COUNT;
    }

    for (i = 0; i < data.nr; ++i) {
        for (j = 0; j < FIDDLE_TWIDDLE_HPC_EVENT_COUNT; ++j) {
            if (data.values[i].id == fiddle_ids[j]) {
                fiddle_snapshot.values[j] =
                    data.values[i].value;
                fiddle_snapshot.valid_mask |=
                    (uint32_t)(1u << j);
                break;
            }
        }
    }
}

static inline void fiddle_apply_group(
    int32_t *a,
    unsigned int len,
    int32_t zeta)
{
    unsigned int j;

    for (j = 0; j < len; ++j) {
        int32_t t =
            PQCLEAN_DILITHIUM2_CLEAN_montgomery_reduce(
                (int64_t)zeta * a[j + len]);
        a[j + len] = a[j] - t;
        a[j] = a[j] + t;
    }
}

/*
 * Baseline: original pointer and original load.
 */
FIDDLE_NOINLINE
void PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_baseline(
    int32_t *a,
    unsigned int len,
    const int32_t *twiddle_pointer)
{
    int32_t zeta;

    __asm__ volatile(
        ".globl fiddle_twiddle_original_load_site\n"
        "fiddle_twiddle_original_load_site:\n\t"
        "movl (%1), %0\n\t"
        : "=r"(zeta)
        : "r"(twiddle_pointer)
        : "memory");

    fiddle_apply_group(a, len, zeta);
}

/*
 * Pointer corruption: the pointer register is already corrupted before this
 * primitive begins.  The measured primitive still performs the original one
 * memory load and every butterfly, but the load uses an unintended address.
 */
FIDDLE_NOINLINE
void PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_corrupt_pointer(
    int32_t *a,
    unsigned int len,
    const int32_t *wrong_twiddle_pointer)
{
    int32_t zeta;

    __asm__ volatile(
        ".globl fiddle_twiddle_corrupt_pointer_load_site\n"
        "fiddle_twiddle_corrupt_pointer_load_site:\n\t"
        "movl (%1), %0\n\t"
        : "=r"(zeta)
        : "r"(wrong_twiddle_pointer)
        : "memory");

    fiddle_apply_group(a, len, zeta);
}

/*
 * Loaded-value corruption: preserve the repository's existing simulation.
 * The selected twiddle load is skipped and the destination value retains the
 * stale zero prepared before PMU enable.  All butterflies still execute.
 */
FIDDLE_NOINLINE
void PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_corrupt_loaded_value(
    int32_t *a,
    unsigned int len,
    int32_t stale_twiddle)
{
    __asm__ volatile(
        ".globl fiddle_twiddle_corrupt_loaded_value_site\n"
        "fiddle_twiddle_corrupt_loaded_value_site:\n\t"
        : "+r"(stale_twiddle)
        :
        : "memory");

    fiddle_apply_group(a, len, stale_twiddle);
}

FIDDLE_NOINLINE
static void fiddle_plain_baseline(
    int32_t *a,
    unsigned int len,
    const int32_t *correct_pointer,
    const int32_t *wrong_pointer,
    int32_t stale_twiddle)
{
    (void)wrong_pointer;
    (void)stale_twiddle;
    PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_baseline(
        a, len, correct_pointer);
}

FIDDLE_NOINLINE
static void fiddle_plain_pointer(
    int32_t *a,
    unsigned int len,
    const int32_t *correct_pointer,
    const int32_t *wrong_pointer,
    int32_t stale_twiddle)
{
    (void)correct_pointer;
    (void)stale_twiddle;
    PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_corrupt_pointer(
        a, len, wrong_pointer);
}

FIDDLE_NOINLINE
static void fiddle_plain_loaded_value(
    int32_t *a,
    unsigned int len,
    const int32_t *correct_pointer,
    const int32_t *wrong_pointer,
    int32_t stale_twiddle)
{
    (void)correct_pointer;
    (void)wrong_pointer;
    PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_corrupt_loaded_value(
        a, len, stale_twiddle);
}

/*
 * The indirect family/mode dispatch occurs before these wrappers are entered.
 * Each wrapper enables counters and then directly calls one fixed target.
 */
FIDDLE_NOINLINE
static void fiddle_measure_baseline(
    int32_t *a,
    unsigned int len,
    const int32_t *correct_pointer,
    const int32_t *wrong_pointer,
    int32_t stale_twiddle)
{
    (void)wrong_pointer;
    (void)stale_twiddle;
    fiddle_snapshot.cpu_before = sched_getcpu();
    fiddle_hpc_begin_unconditional();
    PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_baseline(
        a, len, correct_pointer);
    fiddle_hpc_end_unconditional();
    fiddle_snapshot.cpu_after = sched_getcpu();
}

FIDDLE_NOINLINE
static void fiddle_measure_pointer(
    int32_t *a,
    unsigned int len,
    const int32_t *correct_pointer,
    const int32_t *wrong_pointer,
    int32_t stale_twiddle)
{
    (void)correct_pointer;
    (void)stale_twiddle;
    fiddle_snapshot.cpu_before = sched_getcpu();
    fiddle_hpc_begin_unconditional();
    PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_corrupt_pointer(
        a, len, wrong_pointer);
    fiddle_hpc_end_unconditional();
    fiddle_snapshot.cpu_after = sched_getcpu();
}

FIDDLE_NOINLINE
static void fiddle_measure_loaded_value(
    int32_t *a,
    unsigned int len,
    const int32_t *correct_pointer,
    const int32_t *wrong_pointer,
    int32_t stale_twiddle)
{
    (void)correct_pointer;
    (void)wrong_pointer;
    fiddle_snapshot.cpu_before = sched_getcpu();
    fiddle_hpc_begin_unconditional();
    PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_corrupt_loaded_value(
        a, len, stale_twiddle);
    fiddle_hpc_end_unconditional();
    fiddle_snapshot.cpu_after = sched_getcpu();
}

void PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_configure(
    unsigned int family,
    unsigned int mode,
    unsigned int target_vec,
    unsigned int target_twiddle_index,
    unsigned int pointer_offset)
{
    fiddle_family = family;
    fiddle_mode = mode;
    fiddle_target_vec = target_vec;
    fiddle_target_twiddle_index = target_twiddle_index;
    fiddle_pointer_offset = pointer_offset;

    if (mode == FIDDLE_MODE_BASELINE) {
        fiddle_selected_measured_runner = fiddle_measure_baseline;
        fiddle_selected_plain_runner = fiddle_plain_baseline;
    } else if (family == FIDDLE_FAMILY_POINTER) {
        fiddle_selected_measured_runner = fiddle_measure_pointer;
        fiddle_selected_plain_runner = fiddle_plain_pointer;
    } else {
        fiddle_selected_measured_runner = fiddle_measure_loaded_value;
        fiddle_selected_plain_runner = fiddle_plain_loaded_value;
    }
}

static unsigned int fiddle_wrong_index(unsigned int target)
{
    unsigned int span = (unsigned int)N - 1u;
    unsigned int offset = fiddle_pointer_offset % span;
    unsigned int wrong;

    if (offset == 0u) {
        offset = 1u;
    }

    wrong = 1u + ((target - 1u + offset) % span);
    if (wrong == target) {
        wrong = 1u + (wrong % span);
    }
    return wrong;
}

static void fiddle_run_target_group(
    int32_t *a,
    unsigned int len,
    const int32_t *correct_pointer,
    const int32_t *wrong_pointer,
    int32_t stale_twiddle)
{
    if (fiddle_measurement_enabled && fiddle_hpc_ready) {
        fiddle_selected_measured_runner(
            a,
            len,
            correct_pointer,
            wrong_pointer,
            stale_twiddle);
    } else {
        fiddle_selected_plain_runner(
            a,
            len,
            correct_pointer,
            wrong_pointer,
            stale_twiddle);
    }
}

static void fiddle_instrumented_ntt(int32_t a[N])
{
    const int32_t *zetas =
        PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_zetas();
    int32_t before_group[N];
    int32_t expected_group[N];
    int32_t original_input[N];
    int32_t reference_output[N];
    int32_t stale_twiddle;
    unsigned int wrong_index;
    unsigned int len;
    unsigned int start;
    unsigned int index = 0;
    unsigned int i;
    int target_seen = 0;

    memcpy(original_input, a, sizeof(original_input));
    memset(&fiddle_audit, 0, sizeof(fiddle_audit));

    fiddle_audit.family = fiddle_family;
    fiddle_audit.mode = fiddle_mode;
    fiddle_audit.target_vec = fiddle_target_vec;
    fiddle_audit.target_twiddle_index =
        fiddle_target_twiddle_index;
    fiddle_audit.pointer_offset = fiddle_pointer_offset;
    fiddle_audit.fault_requested =
        fiddle_mode == FIDDLE_MODE_ATTACK;

    stale_twiddle = fiddle_stale_twiddle_zero;
    wrong_index = fiddle_wrong_index(fiddle_target_twiddle_index);
    fiddle_compiler_barrier();

    for (len = 128; len > 0; len >>= 1) {
        for (start = 0; start < (unsigned int)N;
             start += 2u * len) {
            const int32_t *correct_pointer;
            const int32_t *wrong_pointer;
            int32_t correct_twiddle;
            int32_t used_twiddle;
            unsigned int used_index;

            index++;
            correct_pointer = &zetas[index];

            if (index != fiddle_target_twiddle_index) {
                fiddle_apply_group(
                    &a[start],
                    len,
                    *correct_pointer);
                continue;
            }

            target_seen = 1;
            wrong_pointer = &zetas[wrong_index];
            correct_twiddle = *correct_pointer;

            if (fiddle_mode == FIDDLE_MODE_BASELINE) {
                used_twiddle = correct_twiddle;
                used_index = index;
            } else if (fiddle_family == FIDDLE_FAMILY_POINTER) {
                used_twiddle = *wrong_pointer;
                used_index = wrong_index;
            } else {
                used_twiddle = stale_twiddle;
                used_index = index;
            }

            fiddle_audit.correct_twiddle = correct_twiddle;
            fiddle_audit.used_twiddle = used_twiddle;
            fiddle_audit.used_twiddle_index = used_index;
            fiddle_audit.target_len = len;
            fiddle_audit.target_start = start;
            fiddle_audit.pointer_corrupted =
                fiddle_mode == FIDDLE_MODE_ATTACK &&
                fiddle_family == FIDDLE_FAMILY_POINTER;
            fiddle_audit.twiddle_load_skipped =
                fiddle_mode == FIDDLE_MODE_ATTACK &&
                fiddle_family == FIDDLE_FAMILY_LOADED_VALUE;
            fiddle_audit.loaded_value_corrupted =
                fiddle_mode == FIDDLE_MODE_ATTACK &&
                used_twiddle != correct_twiddle;

            memcpy(
                before_group,
                &a[start],
                (size_t)(2u * len) * sizeof(int32_t));
            memcpy(
                expected_group,
                before_group,
                (size_t)(2u * len) * sizeof(int32_t));

            /*
             * The index test, wrong-pointer construction, correct/incorrect
             * value reads for audit, array copies, and family dispatch all
             * occur before the selected measurement wrapper enables counters.
             */
            fiddle_run_target_group(
                &a[start],
                len,
                correct_pointer,
                wrong_pointer,
                stale_twiddle);

            fiddle_apply_group(
                expected_group,
                len,
                correct_twiddle);

            for (i = 0; i < 2u * len; ++i) {
                if (a[start + i] != expected_group[i]) {
                    fiddle_audit.target_group_mismatches++;
                }
            }
        }
    }

    memcpy(reference_output, original_input, sizeof(reference_output));
    PQCLEAN_DILITHIUM2_CLEAN_ntt(reference_output);

    for (i = 0; i < (unsigned int)N; ++i) {
        if (a[i] != reference_output[i]) {
            fiddle_audit.final_ntt_mismatches++;
        }
    }

    if (fiddle_mode == FIDDLE_MODE_BASELINE) {
        fiddle_audit.fault_applied = 0;
        fiddle_audit.semantic_valid =
            target_seen &&
            fiddle_audit.used_twiddle_index ==
                fiddle_audit.target_twiddle_index &&
            fiddle_audit.used_twiddle ==
                fiddle_audit.correct_twiddle &&
            fiddle_audit.pointer_corrupted == 0u &&
            fiddle_audit.twiddle_load_skipped == 0u &&
            fiddle_audit.target_group_mismatches == 0u &&
            fiddle_audit.final_ntt_mismatches == 0u;
    } else if (fiddle_family == FIDDLE_FAMILY_POINTER) {
        fiddle_audit.fault_applied =
            target_seen &&
            fiddle_audit.used_twiddle_index !=
                fiddle_audit.target_twiddle_index &&
            fiddle_audit.pointer_corrupted == 1u &&
            fiddle_audit.twiddle_load_skipped == 0u &&
            fiddle_audit.used_twiddle !=
                fiddle_audit.correct_twiddle &&
            fiddle_audit.target_group_mismatches > 0u;
        fiddle_audit.semantic_valid =
            fiddle_audit.fault_applied &&
            fiddle_audit.final_ntt_mismatches > 0u;
    } else {
        fiddle_audit.fault_applied =
            target_seen &&
            fiddle_audit.used_twiddle_index ==
                fiddle_audit.target_twiddle_index &&
            fiddle_audit.pointer_corrupted == 0u &&
            fiddle_audit.twiddle_load_skipped == 1u &&
            fiddle_audit.used_twiddle == stale_twiddle &&
            fiddle_audit.correct_twiddle != stale_twiddle &&
            fiddle_audit.target_group_mismatches > 0u;
        fiddle_audit.semantic_valid =
            fiddle_audit.fault_applied &&
            fiddle_audit.final_ntt_mismatches > 0u;
    }

    if (!target_seen) {
        fiddle_snapshot.error_code = -ERANGE;
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_polyvecl_ntt(
    polyvecl *value)
{
    unsigned int i;

    fiddle_signing_invocations++;

    if (fiddle_selected_measured_runner == NULL ||
        fiddle_selected_plain_runner == NULL ||
        fiddle_target_vec >= (unsigned int)L ||
        fiddle_target_twiddle_index == 0u ||
        fiddle_target_twiddle_index >= (unsigned int)N) {
        memset(&fiddle_audit, 0, sizeof(fiddle_audit));
        fiddle_snapshot.error_code = -ERANGE;
        PQCLEAN_DILITHIUM2_CLEAN_polyvecl_ntt(value);
        return;
    }

    for (i = 0; i < (unsigned int)L; ++i) {
        if (i == fiddle_target_vec) {
            fiddle_instrumented_ntt(value->vec[i].coeffs);
        } else {
            PQCLEAN_DILITHIUM2_CLEAN_ntt(
                value->vec[i].coeffs);
        }
    }
}
