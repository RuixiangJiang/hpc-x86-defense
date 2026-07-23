#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "krahmer_correction_fault_x86.h"

#include "params.h"
#include "polyvec.h"

#include <errno.h>
#include <linux/perf_event.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef KRAHMER_VARIANT
#define KRAHMER_VARIANT KRAHMER_VARIANT_CORRECTION
#endif

#ifndef KRAHMER_ATTACK_BUILD
#define KRAHMER_ATTACK_BUILD 0
#endif

#ifndef KRAHMER_COUNTER_SET
#define KRAHMER_COUNTER_SET KRAHMER_COUNTER_SET_STRUCTURAL
#endif

#ifndef KRAHMER_PMU_TYPE
#define KRAHMER_PMU_TYPE 4u
#endif

#ifndef KRAHMER_LOAD_CONFIG
#define KRAHMER_LOAD_CONFIG UINT64_C(0x81d0)
#endif

#ifndef KRAHMER_STORE_CONFIG
#define KRAHMER_STORE_CONFIG UINT64_C(0x82d0)
#endif

#if KRAHMER_VARIANT != KRAHMER_VARIANT_CORRECTION && \
    KRAHMER_VARIANT != KRAHMER_VARIANT_A_FAULT
#error "invalid KRAHMER_VARIANT"
#endif

#if KRAHMER_ATTACK_BUILD != 0 && KRAHMER_ATTACK_BUILD != 1
#error "KRAHMER_ATTACK_BUILD must be 0 or 1"
#endif

#if KRAHMER_COUNTER_SET < KRAHMER_COUNTER_SET_STRUCTURAL || \
    KRAHMER_COUNTER_SET > KRAHMER_COUNTER_SET_CACHE_LLC_DTLB
#error "invalid KRAHMER_COUNTER_SET"
#endif

typedef struct {
    const char *name;
    uint32_t type;
    uint64_t config;
} krahmer_event_desc;

#define KRAHMER_CACHE_CONFIG(cache_, op_, result_) \
    ((uint64_t)(cache_) | ((uint64_t)(op_) << 8) | \
     ((uint64_t)(result_) << 16))

#if KRAHMER_COUNTER_SET == KRAHMER_COUNTER_SET_STRUCTURAL

#define KRAHMER_ACTIVE_EVENT_COUNT 6u
static const krahmer_event_desc krahmer_events[
    KRAHMER_ACTIVE_EVENT_COUNT] = {
    {"cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES},
    {"instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS},
    {"branches", PERF_TYPE_HARDWARE,
     PERF_COUNT_HW_BRANCH_INSTRUCTIONS},
    {"branch_misses", PERF_TYPE_HARDWARE,
     PERF_COUNT_HW_BRANCH_MISSES},
    {"retired_loads", KRAHMER_PMU_TYPE, KRAHMER_LOAD_CONFIG},
    {"retired_stores", KRAHMER_PMU_TYPE, KRAHMER_STORE_CONFIG},
};

#elif KRAHMER_COUNTER_SET == KRAHMER_COUNTER_SET_CACHE_L1D

#define KRAHMER_ACTIVE_EVENT_COUNT 4u
static const krahmer_event_desc krahmer_events[
    KRAHMER_ACTIVE_EVENT_COUNT] = {
    {"cache_references", PERF_TYPE_HARDWARE,
     PERF_COUNT_HW_CACHE_REFERENCES},
    {"cache_misses", PERF_TYPE_HARDWARE,
     PERF_COUNT_HW_CACHE_MISSES},
    {"l1d_read_accesses", PERF_TYPE_HW_CACHE,
     KRAHMER_CACHE_CONFIG(
         PERF_COUNT_HW_CACHE_L1D,
         PERF_COUNT_HW_CACHE_OP_READ,
         PERF_COUNT_HW_CACHE_RESULT_ACCESS)},
    {"l1d_read_misses", PERF_TYPE_HW_CACHE,
     KRAHMER_CACHE_CONFIG(
         PERF_COUNT_HW_CACHE_L1D,
         PERF_COUNT_HW_CACHE_OP_READ,
         PERF_COUNT_HW_CACHE_RESULT_MISS)},
};

#else

#define KRAHMER_ACTIVE_EVENT_COUNT 4u
static const krahmer_event_desc krahmer_events[
    KRAHMER_ACTIVE_EVENT_COUNT] = {
    {"llc_read_accesses", PERF_TYPE_HW_CACHE,
     KRAHMER_CACHE_CONFIG(
         PERF_COUNT_HW_CACHE_LL,
         PERF_COUNT_HW_CACHE_OP_READ,
         PERF_COUNT_HW_CACHE_RESULT_ACCESS)},
    {"llc_read_misses", PERF_TYPE_HW_CACHE,
     KRAHMER_CACHE_CONFIG(
         PERF_COUNT_HW_CACHE_LL,
         PERF_COUNT_HW_CACHE_OP_READ,
         PERF_COUNT_HW_CACHE_RESULT_MISS)},
    {"dtlb_read_accesses", PERF_TYPE_HW_CACHE,
     KRAHMER_CACHE_CONFIG(
         PERF_COUNT_HW_CACHE_DTLB,
         PERF_COUNT_HW_CACHE_OP_READ,
         PERF_COUNT_HW_CACHE_RESULT_ACCESS)},
    {"dtlb_read_misses", PERF_TYPE_HW_CACHE,
     KRAHMER_CACHE_CONFIG(
         PERF_COUNT_HW_CACHE_DTLB,
         PERF_COUNT_HW_CACHE_OP_READ,
         PERF_COUNT_HW_CACHE_RESULT_MISS)},
};

#endif

static int krahmer_fds[KRAHMER_HPC_MAX_EVENTS] = {
    -1, -1, -1, -1, -1, -1
};
static uint64_t krahmer_ids[KRAHMER_HPC_MAX_EVENTS];

static int krahmer_hpc_ready;
static int krahmer_measurement_enabled;
static int krahmer_region_counting;

static unsigned int krahmer_target_vec;
static unsigned int krahmer_target_coeff = 17u;
static unsigned int krahmer_target_row;
static unsigned int krahmer_target_col;
static unsigned int krahmer_target_a_coeff = 17u;
static uint64_t krahmer_target_invocations;

static int32_t krahmer_saved_a_value;
static polyvecl *krahmer_prepared_matrix;

static krahmer_hpc_snapshot krahmer_snapshot;
static krahmer_audit_snapshot krahmer_audit;

typedef struct {
    uint64_t value;
    uint64_t id;
} krahmer_read_value;

typedef struct {
    uint64_t nr;
    uint64_t time_enabled;
    uint64_t time_running;
    krahmer_read_value values[KRAHMER_HPC_MAX_EVENTS];
} krahmer_group_read;

static long krahmer_perf_event_open(
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

static inline void krahmer_compiler_barrier(void)
{
    __asm__ volatile("" ::: "memory");
}

static void krahmer_close_all(void)
{
    unsigned int i;

    for (i = 0; i < KRAHMER_HPC_MAX_EVENTS; ++i) {
        if (krahmer_fds[i] >= 0) {
            close(krahmer_fds[i]);
            krahmer_fds[i] = -1;
        }
        krahmer_ids[i] = 0;
    }

    krahmer_hpc_ready = 0;
}

int PQCLEAN_DILITHIUM2_CLEAN_krahmer_hpc_init(void)
{
    struct perf_event_attr attr;
    int leader = -1;
    unsigned int i;

    krahmer_close_all();
    memset(&krahmer_snapshot, 0, sizeof(krahmer_snapshot));

    for (i = 0; i < KRAHMER_ACTIVE_EVENT_COUNT; ++i) {
        memset(&attr, 0, sizeof(attr));
        attr.size = sizeof(attr);
        attr.type = krahmer_events[i].type;
        attr.config = krahmer_events[i].config;
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

        krahmer_fds[i] = (int)krahmer_perf_event_open(
            &attr,
            0,
            -1,
            leader,
            PERF_FLAG_FD_CLOEXEC);

        if (krahmer_fds[i] < 0) {
            int saved = errno;
            krahmer_close_all();
            krahmer_snapshot.error_code = -saved;
            return -saved;
        }

        if (i == 0u) {
            leader = krahmer_fds[i];
        }

        if (ioctl(
                krahmer_fds[i],
                PERF_EVENT_IOC_ID,
                &krahmer_ids[i]) != 0) {
            int saved = errno;
            krahmer_close_all();
            krahmer_snapshot.error_code = -saved;
            return -saved;
        }
    }

    krahmer_hpc_ready = 1;
    krahmer_snapshot.error_code = 0;
    return 0;
}

void PQCLEAN_DILITHIUM2_CLEAN_krahmer_hpc_close(void)
{
    krahmer_close_all();
}

unsigned int PQCLEAN_DILITHIUM2_CLEAN_krahmer_event_count(void)
{
    return KRAHMER_ACTIVE_EVENT_COUNT;
}

const char *PQCLEAN_DILITHIUM2_CLEAN_krahmer_event_name(
    unsigned int index)
{
    if (index >= KRAHMER_ACTIVE_EVENT_COUNT) {
        return "unknown";
    }
    return krahmer_events[index].name;
}

const char *PQCLEAN_DILITHIUM2_CLEAN_krahmer_counter_set_name(void)
{
#if KRAHMER_COUNTER_SET == KRAHMER_COUNTER_SET_STRUCTURAL
    return "structural";
#elif KRAHMER_COUNTER_SET == KRAHMER_COUNTER_SET_CACHE_L1D
    return "cache-l1d";
#else
    return "cache-llc-dtlb";
#endif
}

void PQCLEAN_DILITHIUM2_CLEAN_krahmer_configure(
    unsigned int target_vec,
    unsigned int target_coeff,
    unsigned int target_row,
    unsigned int target_col,
    unsigned int target_a_coeff)
{
    krahmer_target_vec = target_vec;
    krahmer_target_coeff = target_coeff;
    krahmer_target_row = target_row;
    krahmer_target_col = target_col;
    krahmer_target_a_coeff = target_a_coeff;
}

void PQCLEAN_DILITHIUM2_CLEAN_krahmer_set_measurement_enabled(
    int enabled)
{
    krahmer_measurement_enabled = enabled != 0;
}

void PQCLEAN_DILITHIUM2_CLEAN_krahmer_get_hpc_snapshot(
    krahmer_hpc_snapshot *out)
{
    if (out != NULL) {
        *out = krahmer_snapshot;
        out->target_invocations = krahmer_target_invocations;
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_krahmer_get_audit_snapshot(
    krahmer_audit_snapshot *out)
{
    if (out != NULL) {
        *out = krahmer_audit;
    }
}

static inline void krahmer_hpc_begin_unconditional(void)
{
    krahmer_snapshot.error_code = 0;
    krahmer_compiler_barrier();

    if (ioctl(
            krahmer_fds[0],
            PERF_EVENT_IOC_RESET,
            PERF_IOC_FLAG_GROUP) != 0) {
        krahmer_snapshot.error_code = -errno;
    }

    if (ioctl(
            krahmer_fds[0],
            PERF_EVENT_IOC_ENABLE,
            PERF_IOC_FLAG_GROUP) != 0) {
        krahmer_snapshot.error_code = -errno;
    }

    krahmer_compiler_barrier();
}

static void krahmer_hpc_end_unconditional(void)
{
    krahmer_group_read data;
    ssize_t got;
    unsigned int i;
    unsigned int j;

    krahmer_compiler_barrier();

    if (ioctl(
            krahmer_fds[0],
            PERF_EVENT_IOC_DISABLE,
            PERF_IOC_FLAG_GROUP) != 0) {
        krahmer_snapshot.error_code = -errno;
    }

    krahmer_compiler_barrier();
    memset(&data, 0, sizeof(data));
    got = read(krahmer_fds[0], &data, sizeof(data));

    krahmer_snapshot.sequence++;
    krahmer_snapshot.target_invocations =
        krahmer_target_invocations;
    krahmer_snapshot.active_event_count =
        KRAHMER_ACTIVE_EVENT_COUNT;
    krahmer_snapshot.counter_set = KRAHMER_COUNTER_SET;
    krahmer_snapshot.variant = KRAHMER_VARIANT;
    krahmer_snapshot.attack_build = KRAHMER_ATTACK_BUILD;
    krahmer_snapshot.target_vec = krahmer_target_vec;
    krahmer_snapshot.target_coeff = krahmer_target_coeff;
    krahmer_snapshot.target_row = krahmer_target_row;
    krahmer_snapshot.target_col = krahmer_target_col;
    krahmer_snapshot.target_a_coeff = krahmer_target_a_coeff;
    krahmer_snapshot.valid_mask = 0;
    memset(
        krahmer_snapshot.values,
        0,
        sizeof(krahmer_snapshot.values));

    if (got < (ssize_t)(3u * sizeof(uint64_t))) {
        krahmer_snapshot.error_code =
            (got < 0) ? -errno : -EIO;
        return;
    }

    krahmer_snapshot.time_enabled = data.time_enabled;
    krahmer_snapshot.time_running = data.time_running;

    if (data.nr > KRAHMER_ACTIVE_EVENT_COUNT) {
        data.nr = KRAHMER_ACTIVE_EVENT_COUNT;
    }

    for (i = 0; i < data.nr; ++i) {
        for (j = 0; j < KRAHMER_ACTIVE_EVENT_COUNT; ++j) {
            if (data.values[i].id == krahmer_ids[j]) {
                krahmer_snapshot.values[j] =
                    data.values[i].value;
                krahmer_snapshot.valid_mask |=
                    (uint32_t)(1u << j);
                break;
            }
        }
    }
}

__asm__(
    ".text\n"
    ".p2align 4\n"
    ".globl PQCLEAN_DILITHIUM2_CLEAN_krahmer_correction_target_baseline\n"
    ".type PQCLEAN_DILITHIUM2_CLEAN_krahmer_correction_target_baseline,"
    " @function\n"
    "PQCLEAN_DILITHIUM2_CLEAN_krahmer_correction_target_baseline:\n"
    ".globl krahmer_correction_add_site\n"
    "krahmer_correction_add_site:\n"
    "movl (%rsi), %eax\n"
    "movl (%rdx), %ecx\n"
    "addl %ecx, %eax\n"
    "movl %eax, (%rdi)\n"
    "ret\n"
    ".size PQCLEAN_DILITHIUM2_CLEAN_krahmer_correction_target_baseline,"
    " .-PQCLEAN_DILITHIUM2_CLEAN_krahmer_correction_target_baseline\n"
    ".p2align 4\n"
    ".globl PQCLEAN_DILITHIUM2_CLEAN_krahmer_correction_target_skip\n"
    ".type PQCLEAN_DILITHIUM2_CLEAN_krahmer_correction_target_skip,"
    " @function\n"
    "PQCLEAN_DILITHIUM2_CLEAN_krahmer_correction_target_skip:\n"
    ".globl krahmer_correction_skipped_add_site\n"
    "krahmer_correction_skipped_add_site:\n"
    "movl (%rsi), %eax\n"
    "movl (%rdx), %ecx\n"
    "movl %eax, (%rdi)\n"
    "ret\n"
    ".size PQCLEAN_DILITHIUM2_CLEAN_krahmer_correction_target_skip,"
    " .-PQCLEAN_DILITHIUM2_CLEAN_krahmer_correction_target_skip\n"
);

void PQCLEAN_DILITHIUM2_CLEAN_krahmer_correction_apply(
    polyvecl *z,
    const polyvecl *y)
{
    unsigned int flat_target =
        krahmer_target_vec * (unsigned int)N +
        krahmer_target_coeff;
    unsigned int total = (unsigned int)L * (unsigned int)N;
    unsigned int flat;
    int32_t *z_flat = &z->vec[0].coeffs[0];
    const int32_t *y_flat = &y->vec[0].coeffs[0];
    int32_t base_value;
    int32_t correction_value;

    krahmer_target_invocations++;
    memset(&krahmer_audit, 0, sizeof(krahmer_audit));
    krahmer_audit.variant = KRAHMER_VARIANT;
    krahmer_audit.attack_build = KRAHMER_ATTACK_BUILD;
    krahmer_audit.target_vec = krahmer_target_vec;
    krahmer_audit.target_coeff = krahmer_target_coeff;
    krahmer_audit.target_row = krahmer_target_row;
    krahmer_audit.target_col = krahmer_target_col;
    krahmer_audit.target_a_coeff = krahmer_target_a_coeff;
    krahmer_audit.fault_requested = KRAHMER_ATTACK_BUILD;

    if (flat_target >= total) {
        krahmer_snapshot.error_code = -ERANGE;
        PQCLEAN_DILITHIUM2_CLEAN_polyvecl_add(z, z, y);
        return;
    }

    for (flat = 0; flat < flat_target; ++flat) {
        z_flat[flat] += y_flat[flat];
    }

    base_value = z_flat[flat_target];
    correction_value = y_flat[flat_target];

    krahmer_audit.correction_base = base_value;
    krahmer_audit.correction_term = correction_value;
    krahmer_audit.correction_expected =
        base_value + correction_value;

    if (krahmer_measurement_enabled && krahmer_hpc_ready) {
        krahmer_hpc_begin_unconditional();
#if KRAHMER_ATTACK_BUILD == 0
        PQCLEAN_DILITHIUM2_CLEAN_krahmer_correction_target_baseline(
            &z_flat[flat_target],
            &base_value,
            &correction_value);
#else
        PQCLEAN_DILITHIUM2_CLEAN_krahmer_correction_target_skip(
            &z_flat[flat_target],
            &base_value,
            &correction_value);
#endif
        krahmer_hpc_end_unconditional();
    } else {
#if KRAHMER_ATTACK_BUILD == 0
        PQCLEAN_DILITHIUM2_CLEAN_krahmer_correction_target_baseline(
            &z_flat[flat_target],
            &base_value,
            &correction_value);
#else
        PQCLEAN_DILITHIUM2_CLEAN_krahmer_correction_target_skip(
            &z_flat[flat_target],
            &base_value,
            &correction_value);
#endif
    }

    krahmer_audit.correction_used = z_flat[flat_target];

    for (flat = flat_target + 1u; flat < total; ++flat) {
        z_flat[flat] += y_flat[flat];
    }

#if KRAHMER_ATTACK_BUILD == 0
    krahmer_audit.fault_applied = 0u;
    krahmer_audit.semantic_valid =
        krahmer_audit.correction_used ==
        krahmer_audit.correction_expected;
#else
    krahmer_audit.fault_applied =
        krahmer_audit.correction_used ==
            krahmer_audit.correction_base &&
        krahmer_audit.correction_used !=
            krahmer_audit.correction_expected;
    krahmer_audit.semantic_valid =
        krahmer_audit.fault_applied;
#endif
}

void PQCLEAN_DILITHIUM2_CLEAN_krahmer_matrix_prepare(
    polyvecl mat[K])
{
    unsigned int row = krahmer_target_row;
    unsigned int col = krahmer_target_col;
    unsigned int coeff = krahmer_target_a_coeff;

    krahmer_target_invocations++;
    memset(&krahmer_audit, 0, sizeof(krahmer_audit));
    krahmer_audit.variant = KRAHMER_VARIANT;
    krahmer_audit.attack_build = KRAHMER_ATTACK_BUILD;
    krahmer_audit.target_vec = krahmer_target_vec;
    krahmer_audit.target_coeff = krahmer_target_coeff;
    krahmer_audit.target_row = row;
    krahmer_audit.target_col = col;
    krahmer_audit.target_a_coeff = coeff;
    krahmer_audit.fault_requested = KRAHMER_ATTACK_BUILD;

    if (row >= (unsigned int)K ||
        col >= (unsigned int)L ||
        coeff >= (unsigned int)N) {
        krahmer_snapshot.error_code = -ERANGE;
        krahmer_prepared_matrix = NULL;
        return;
    }

    {
        volatile int32_t *target =
            &mat[row].vec[col].coeffs[coeff];

        krahmer_saved_a_value = *target;
        krahmer_audit.a_original = krahmer_saved_a_value;

        /*
         * Equalize the pre-window cache state: both builds execute one
         * volatile store to the same matrix address. Baseline stores the
         * original value back; attack stores zero. The measured consumer then
         * performs the same loads from the same addresses in both builds.
         */
#if KRAHMER_ATTACK_BUILD == 1
        *target = 0;
#else
        *target = krahmer_saved_a_value;
#endif
        krahmer_audit.a_faulty = *target;
    }

    krahmer_prepared_matrix = mat;
    krahmer_compiler_barrier();
}

void PQCLEAN_DILITHIUM2_CLEAN_krahmer_matrix_region_begin(void)
{
    krahmer_region_counting =
        krahmer_measurement_enabled && krahmer_hpc_ready;

    if (krahmer_region_counting) {
        krahmer_hpc_begin_unconditional();
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_krahmer_matrix_region_stop(void)
{
    /*
     * Keep PMU shutdown in a dedicated function whose body is identical in
     * baseline and attack builds. The previous combined region_end() function
     * contained attack-only restoration code after the stop call; that changed
     * its prologue and leaked extra instructions/loads/stores into the window.
     */
    if (krahmer_region_counting) {
        krahmer_hpc_end_unconditional();
    }
    krahmer_region_counting = 0;
    krahmer_compiler_barrier();
}

void PQCLEAN_DILITHIUM2_CLEAN_krahmer_matrix_audit(
    const polyveck *out,
    polyvecl mat[K],
    const polyvecl *value)
{
    polyveck reference;
    unsigned int row = krahmer_target_row;
    unsigned int col = krahmer_target_col;
    unsigned int coeff = krahmer_target_a_coeff;
    unsigned int i;
    unsigned int j;
    unsigned int mismatches = 0;

    /*
     * This function is called only after matrix_region_stop(), so restoration,
     * reference computation, and audit cannot affect the measured counters.
     */
    if (krahmer_prepared_matrix == NULL ||
        mat != krahmer_prepared_matrix) {
        krahmer_snapshot.error_code = -ERANGE;
        return;
    }

#if KRAHMER_ATTACK_BUILD == 1
    mat[row].vec[col].coeffs[coeff] =
        krahmer_saved_a_value;
#endif
    krahmer_compiler_barrier();

    PQCLEAN_DILITHIUM2_CLEAN_polyvec_matrix_pointwise_montgomery(
        &reference,
        mat,
        value);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_reduce(&reference);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_invntt_tomont(&reference);

    for (i = 0; i < (unsigned int)K; ++i) {
        for (j = 0; j < (unsigned int)N; ++j) {
            if (out->vec[i].coeffs[j] !=
                reference.vec[i].coeffs[j]) {
                mismatches++;
            }
        }
    }

    krahmer_audit.matrix_output_mismatches = mismatches;

#if KRAHMER_ATTACK_BUILD == 0
    krahmer_audit.fault_applied = 0u;
    krahmer_audit.semantic_valid =
        krahmer_audit.a_original != 0 &&
        krahmer_audit.a_faulty ==
            krahmer_audit.a_original &&
        mismatches == 0u;
#else
    krahmer_audit.fault_applied =
        krahmer_audit.a_original != 0 &&
        krahmer_audit.a_faulty == 0 &&
        mismatches > 0u;
    krahmer_audit.semantic_valid =
        krahmer_audit.fault_applied;
#endif

    krahmer_prepared_matrix = NULL;
}
