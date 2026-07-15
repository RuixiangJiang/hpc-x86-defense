#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "krahmer_correction_fault_x86.h"

#include "params.h"
#include "polyvec.h"
#include "krahmer_microarch_events_generated.h"

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

#if KRAHMER_VARIANT != KRAHMER_VARIANT_CORRECTION && \
    KRAHMER_VARIANT != KRAHMER_VARIANT_A_FAULT
#error "invalid KRAHMER_VARIANT"
#endif

#if KRAHMER_ATTACK_BUILD != 0 && KRAHMER_ATTACK_BUILD != 1
#error "KRAHMER_ATTACK_BUILD must be 0 or 1"
#endif

#if KRAHMER_COUNTER_SET < KRAHMER_COUNTER_SET_STRUCTURAL || \
    KRAHMER_COUNTER_SET > KRAHMER_COUNTER_SET_RECOVERY
#error "invalid KRAHMER_COUNTER_SET"
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

#if defined(__GNUC__) || defined(__clang__)
#define KRAHMER_NOINLINE __attribute__((noinline, noclone, used))
#else
#define KRAHMER_NOINLINE
#endif

typedef struct {
    const char *name;
    uint32_t type;
    uint64_t config;
    uint64_t config1;
    uint64_t config2;
    uint32_t precise_ip;
    uint32_t available;
} krahmer_event_desc;

#define KRAHMER_EVENT_GENERIC(name_, config_) \
    {name_, PERF_TYPE_HARDWARE, config_, UINT64_C(0), UINT64_C(0), 0u, 1u}

#define KRAHMER_EVENT_RAW(name_, macro_) \
    { \
        name_, \
        KRAHMER_EVT_##macro_##_TYPE, \
        KRAHMER_EVT_##macro_##_CONFIG, \
        KRAHMER_EVT_##macro_##_CONFIG1, \
        KRAHMER_EVT_##macro_##_CONFIG2, \
        KRAHMER_EVT_##macro_##_PRECISE_IP, \
        KRAHMER_EVT_##macro_##_AVAILABLE \
    }

#define KRAHMER_CACHE_CONFIG(cache, op, result) \
    ((uint64_t)(cache) | \
     ((uint64_t)(op) << 8) | \
     ((uint64_t)(result) << 16))

#if KRAHMER_COUNTER_SET == KRAHMER_COUNTER_SET_STRUCTURAL
static const krahmer_event_desc krahmer_events[
    KRAHMER_HPC_EVENT_COUNT] = {
    KRAHMER_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    KRAHMER_EVENT_GENERIC("instructions", PERF_COUNT_HW_INSTRUCTIONS),
    KRAHMER_EVENT_GENERIC("branches", PERF_COUNT_HW_BRANCH_INSTRUCTIONS),
    KRAHMER_EVENT_GENERIC("branch_misses", PERF_COUNT_HW_BRANCH_MISSES),
    {
        "retired_loads",
        KRAHMER_PMU_TYPE,
        KRAHMER_LOAD_CONFIG,
        UINT64_C(0),
        UINT64_C(0),
        0u,
        1u
    },
    {
        "retired_stores",
        KRAHMER_PMU_TYPE,
        KRAHMER_STORE_CONFIG,
        UINT64_C(0),
        UINT64_C(0),
        0u,
        1u
    },
};
#elif KRAHMER_COUNTER_SET == KRAHMER_COUNTER_SET_CACHE
static const krahmer_event_desc krahmer_events[
    KRAHMER_HPC_EVENT_COUNT] = {
    KRAHMER_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    KRAHMER_EVENT_GENERIC("instructions", PERF_COUNT_HW_INSTRUCTIONS),
    {
        "l1d_read_misses",
        PERF_TYPE_HW_CACHE,
        KRAHMER_CACHE_CONFIG(
            PERF_COUNT_HW_CACHE_L1D,
            PERF_COUNT_HW_CACHE_OP_READ,
            PERF_COUNT_HW_CACHE_RESULT_MISS),
        UINT64_C(0),
        UINT64_C(0),
        0u,
        1u
    },
    {
        "l1i_read_misses",
        PERF_TYPE_HW_CACHE,
        KRAHMER_CACHE_CONFIG(
            PERF_COUNT_HW_CACHE_L1I,
            PERF_COUNT_HW_CACHE_OP_READ,
            PERF_COUNT_HW_CACHE_RESULT_MISS),
        UINT64_C(0),
        UINT64_C(0),
        0u,
        1u
    },
    {
        "llc_read_misses",
        PERF_TYPE_HW_CACHE,
        KRAHMER_CACHE_CONFIG(
            PERF_COUNT_HW_CACHE_LL,
            PERF_COUNT_HW_CACHE_OP_READ,
            PERF_COUNT_HW_CACHE_RESULT_MISS),
        UINT64_C(0),
        UINT64_C(0),
        0u,
        1u
    },
    {
        "dtlb_read_misses",
        PERF_TYPE_HW_CACHE,
        KRAHMER_CACHE_CONFIG(
            PERF_COUNT_HW_CACHE_DTLB,
            PERF_COUNT_HW_CACHE_OP_READ,
            PERF_COUNT_HW_CACHE_RESULT_MISS),
        UINT64_C(0),
        UINT64_C(0),
        0u,
        1u
    },
};
#elif KRAHMER_COUNTER_SET == KRAHMER_COUNTER_SET_CACHE_DETAIL
static const krahmer_event_desc krahmer_events[
    KRAHMER_HPC_EVENT_COUNT] = {
    KRAHMER_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    KRAHMER_EVENT_GENERIC("instructions", PERF_COUNT_HW_INSTRUCTIONS),
    KRAHMER_EVENT_GENERIC("cache_references", PERF_COUNT_HW_CACHE_REFERENCES),
    KRAHMER_EVENT_GENERIC("cache_misses", PERF_COUNT_HW_CACHE_MISSES),
    KRAHMER_EVENT_RAW("l1d_replacements", L1D_REPLACEMENTS),
    KRAHMER_EVENT_RAW("l2_request_misses", L2_REQUEST_MISSES),
};
#elif KRAHMER_COUNTER_SET == KRAHMER_COUNTER_SET_LOAD_HITS
static const krahmer_event_desc krahmer_events[
    KRAHMER_HPC_EVENT_COUNT] = {
    KRAHMER_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    KRAHMER_EVENT_GENERIC("instructions", PERF_COUNT_HW_INSTRUCTIONS),
    KRAHMER_EVENT_RAW("load_l1_hit", LOAD_L1_HIT),
    KRAHMER_EVENT_RAW("load_l2_hit", LOAD_L2_HIT),
    KRAHMER_EVENT_RAW("load_l3_hit", LOAD_L3_HIT),
    KRAHMER_EVENT_RAW("load_l3_miss", LOAD_L3_MISS),
};
#elif KRAHMER_COUNTER_SET == KRAHMER_COUNTER_SET_LOAD_MISSES_LATENCY
static const krahmer_event_desc krahmer_events[
    KRAHMER_HPC_EVENT_COUNT] = {
    KRAHMER_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    KRAHMER_EVENT_GENERIC("instructions", PERF_COUNT_HW_INSTRUCTIONS),
    KRAHMER_EVENT_RAW("load_l1_miss", LOAD_L1_MISS),
    KRAHMER_EVENT_RAW("load_l2_miss", LOAD_L2_MISS),
    KRAHMER_EVENT_RAW("load_l3_miss", LOAD_L3_MISS),
    KRAHMER_EVENT_RAW("long_latency_loads", LONG_LATENCY_LOADS),
};
#elif KRAHMER_COUNTER_SET == KRAHMER_COUNTER_SET_STALLS
static const krahmer_event_desc krahmer_events[
    KRAHMER_HPC_EVENT_COUNT] = {
    KRAHMER_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    KRAHMER_EVENT_GENERIC("instructions", PERF_COUNT_HW_INSTRUCTIONS),
    KRAHMER_EVENT_GENERIC(
        "stalled_frontend_cycles",
        PERF_COUNT_HW_STALLED_CYCLES_FRONTEND),
    KRAHMER_EVENT_GENERIC(
        "stalled_backend_cycles",
        PERF_COUNT_HW_STALLED_CYCLES_BACKEND),
    KRAHMER_EVENT_RAW("stalls_l1d_miss", STALLS_L1D_MISS),
    KRAHMER_EVENT_RAW("stalls_mem_any", STALLS_MEM_ANY),
};
#elif KRAHMER_COUNTER_SET == KRAHMER_COUNTER_SET_RECOVERY
static const krahmer_event_desc krahmer_events[
    KRAHMER_HPC_EVENT_COUNT] = {
    KRAHMER_EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    KRAHMER_EVENT_GENERIC("instructions", PERF_COUNT_HW_INSTRUCTIONS),
    KRAHMER_EVENT_RAW("machine_clears", MACHINE_CLEARS),
    KRAHMER_EVENT_RAW(
        "memory_ordering_clears",
        MEMORY_ORDERING_CLEARS),
    KRAHMER_EVENT_RAW("recovery_cycles", RECOVERY_CYCLES),
    KRAHMER_EVENT_RAW(
        "recovery_cycles_any",
        RECOVERY_CYCLES_ANY),
};
#else
#error "invalid KRAHMER_COUNTER_SET"
#endif

static int krahmer_fds[KRAHMER_HPC_EVENT_COUNT] = {
    -1, -1, -1, -1, -1, -1
};
static uint64_t krahmer_ids[KRAHMER_HPC_EVENT_COUNT];
static uint32_t krahmer_requested_mask;
static uint32_t krahmer_available_mask;
static uint32_t krahmer_open_error_mask;

static int krahmer_hpc_ready;
static int krahmer_measurement_enabled;
static unsigned int krahmer_target_vec;
static unsigned int krahmer_target_coeff = 17u;
static unsigned int krahmer_target_row;
static unsigned int krahmer_target_col;
static unsigned int krahmer_target_a_coeff = 17u;
static uint32_t krahmer_a_xor_mask = 1u;
static uint64_t krahmer_target_invocations;

static krahmer_hpc_snapshot krahmer_snapshot;
static krahmer_audit_snapshot krahmer_audit;

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

static void krahmer_close_all(void)
{
    unsigned int i;

    for (i = 0; i < KRAHMER_HPC_EVENT_COUNT; ++i) {
        if (krahmer_fds[i] >= 0) {
            close(krahmer_fds[i]);
            krahmer_fds[i] = -1;
        }
        krahmer_ids[i] = 0;
    }

    krahmer_hpc_ready = 0;
    krahmer_requested_mask = 0;
    krahmer_available_mask = 0;
    krahmer_open_error_mask = 0;
}

int PQCLEAN_DILITHIUM2_CLEAN_krahmer_hpc_init(void)
{
    struct perf_event_attr attr;
    int leader = -1;
    unsigned int i;

    krahmer_close_all();
    memset(&krahmer_snapshot, 0, sizeof(krahmer_snapshot));

    for (i = 0; i < KRAHMER_HPC_EVENT_COUNT; ++i) {
        int saved;

        if (!krahmer_events[i].available) {
            continue;
        }

        krahmer_requested_mask |= (uint32_t)(1u << i);

        memset(&attr, 0, sizeof(attr));
        attr.size = sizeof(attr);
        attr.type = krahmer_events[i].type;
        attr.config = krahmer_events[i].config;
        attr.config1 = krahmer_events[i].config1;
        attr.config2 = krahmer_events[i].config2;
        attr.precise_ip = krahmer_events[i].precise_ip;
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
            saved = errno;
            if (i < 2u) {
                krahmer_close_all();
                krahmer_snapshot.error_code = -saved;
                return -saved;
            }
            krahmer_open_error_mask |= (uint32_t)(1u << i);
            continue;
        }

        if (i == 0u) {
            leader = krahmer_fds[i];
        }

        if (ioctl(
                krahmer_fds[i],
                PERF_EVENT_IOC_ID,
                &krahmer_ids[i]) != 0) {
            saved = errno;
            close(krahmer_fds[i]);
            krahmer_fds[i] = -1;
            if (i < 2u) {
                krahmer_close_all();
                krahmer_snapshot.error_code = -saved;
                return -saved;
            }
            krahmer_open_error_mask |= (uint32_t)(1u << i);
            continue;
        }

        krahmer_available_mask |= (uint32_t)(1u << i);
    }

    if ((krahmer_available_mask & UINT32_C(0x3)) != UINT32_C(0x3)) {
        krahmer_close_all();
        krahmer_snapshot.error_code = -ENODEV;
        return -ENODEV;
    }

    krahmer_snapshot.requested_mask = krahmer_requested_mask;
    krahmer_snapshot.available_mask = krahmer_available_mask;
    krahmer_snapshot.open_error_mask = krahmer_open_error_mask;
    krahmer_hpc_ready = 1;
    krahmer_snapshot.error_code = 0;
    return 0;
}

void PQCLEAN_DILITHIUM2_CLEAN_krahmer_hpc_close(void)
{
    krahmer_close_all();
}

void PQCLEAN_DILITHIUM2_CLEAN_krahmer_configure(
    unsigned int target_vec,
    unsigned int target_coeff,
    unsigned int target_row,
    unsigned int target_col,
    unsigned int target_a_coeff,
    uint32_t a_xor_mask)
{
    krahmer_target_vec = target_vec;
    krahmer_target_coeff = target_coeff;
    krahmer_target_row = target_row;
    krahmer_target_col = target_col;
    krahmer_target_a_coeff = target_a_coeff;
    krahmer_a_xor_mask = a_xor_mask;
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

const char *PQCLEAN_DILITHIUM2_CLEAN_krahmer_event_name(
    unsigned int index)
{
    if (index >= KRAHMER_HPC_EVENT_COUNT) {
        return "unknown";
    }
    return krahmer_events[index].name;
}

static inline void krahmer_compiler_barrier(void)
{
    __asm__ volatile("" ::: "memory");
}

typedef struct {
    uint64_t value;
    uint64_t id;
} krahmer_read_value;

typedef struct {
    uint64_t nr;
    uint64_t time_enabled;
    uint64_t time_running;
    krahmer_read_value values[KRAHMER_HPC_EVENT_COUNT];
} krahmer_group_read;

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
    krahmer_snapshot.variant = KRAHMER_VARIANT;
    krahmer_snapshot.attack_build = KRAHMER_ATTACK_BUILD;
    krahmer_snapshot.target_vec = krahmer_target_vec;
    krahmer_snapshot.target_coeff = krahmer_target_coeff;
    krahmer_snapshot.target_row = krahmer_target_row;
    krahmer_snapshot.target_col = krahmer_target_col;
    krahmer_snapshot.target_a_coeff = krahmer_target_a_coeff;
    krahmer_snapshot.requested_mask = krahmer_requested_mask;
    krahmer_snapshot.available_mask = krahmer_available_mask;
    krahmer_snapshot.open_error_mask = krahmer_open_error_mask;
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

    if (data.nr > KRAHMER_HPC_EVENT_COUNT) {
        data.nr = KRAHMER_HPC_EVENT_COUNT;
    }

    for (i = 0; i < data.nr; ++i) {
        for (j = 0; j < KRAHMER_HPC_EVENT_COUNT; ++j) {
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

/*
 * The two correction primitives have no runtime mode branch.
 *
 * Both explicitly load the uncorrected value and the correction term.
 * The faulted primitive omits only the local addition and writes the
 * uncorrected value.  Thus the correction term is available, but is not
 * incorporated into the target coefficient.
 */
KRAHMER_NOINLINE
void PQCLEAN_DILITHIUM2_CLEAN_krahmer_correction_target_baseline(
    int32_t *destination,
    const int32_t *base,
    const int32_t *correction)
{
    int32_t base_value = *base;
    int32_t correction_value = *correction;

    __asm__ volatile(
        ".globl krahmer_correction_add_site\n"
        "krahmer_correction_add_site:\n\t"
        : "+r"(base_value), "+r"(correction_value)
        :
        : "memory");

    *destination = base_value + correction_value;
}

KRAHMER_NOINLINE
void PQCLEAN_DILITHIUM2_CLEAN_krahmer_correction_target_skip(
    int32_t *destination,
    const int32_t *base,
    const int32_t *correction)
{
    int32_t base_value = *base;
    int32_t correction_value = *correction;

    __asm__ volatile(
        ".globl krahmer_correction_skipped_add_site\n"
        "krahmer_correction_skipped_add_site:\n\t"
        : "+r"(base_value), "+r"(correction_value)
        :
        : "memory");

    *destination = base_value;
}

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
    int32_t expected_value;

    krahmer_target_invocations++;
    memset(&krahmer_audit, 0, sizeof(krahmer_audit));
    krahmer_audit.variant = KRAHMER_VARIANT;
    krahmer_audit.attack_build = KRAHMER_ATTACK_BUILD;
    krahmer_audit.target_vec = krahmer_target_vec;
    krahmer_audit.target_coeff = krahmer_target_coeff;
    krahmer_audit.target_row = krahmer_target_row;
    krahmer_audit.target_col = krahmer_target_col;
    krahmer_audit.target_a_coeff = krahmer_target_a_coeff;
    krahmer_audit.a_xor_mask = krahmer_a_xor_mask;
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
    expected_value = base_value + correction_value;

    krahmer_audit.correction_base = base_value;
    krahmer_audit.correction_term = correction_value;
    krahmer_audit.correction_expected = expected_value;

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
    krahmer_audit.fault_applied = 0;
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

/*
 * This consumer is identical in A-baseline and A-fault builds.
 * The matrix data state is prepared before the PMU begins.
 */
KRAHMER_NOINLINE
void PQCLEAN_DILITHIUM2_CLEAN_krahmer_matrix_consume(
    polyveck *out,
    const polyvecl mat[K],
    const polyvecl *value)
{
    PQCLEAN_DILITHIUM2_CLEAN_polyvec_matrix_pointwise_montgomery(
        out,
        mat,
        value);
}

void PQCLEAN_DILITHIUM2_CLEAN_krahmer_matrix_apply(
    polyveck *out,
    polyvecl mat[K],
    const polyvecl *value)
{
    polyveck reference;
    int32_t original;
    int32_t faulty;
    unsigned int row;
    unsigned int col;
    unsigned int coeff;
    unsigned int i;
    unsigned int j;
    unsigned int mismatches = 0;

    krahmer_target_invocations++;
    memset(&krahmer_audit, 0, sizeof(krahmer_audit));
    krahmer_audit.variant = KRAHMER_VARIANT;
    krahmer_audit.attack_build = KRAHMER_ATTACK_BUILD;
    krahmer_audit.target_vec = krahmer_target_vec;
    krahmer_audit.target_coeff = krahmer_target_coeff;
    krahmer_audit.target_row = krahmer_target_row;
    krahmer_audit.target_col = krahmer_target_col;
    krahmer_audit.target_a_coeff = krahmer_target_a_coeff;
    krahmer_audit.a_xor_mask = krahmer_a_xor_mask;
    krahmer_audit.fault_requested = KRAHMER_ATTACK_BUILD;

    row = krahmer_target_row;
    col = krahmer_target_col;
    coeff = krahmer_target_a_coeff;

    if (row >= (unsigned int)K ||
        col >= (unsigned int)L ||
        coeff >= (unsigned int)N ||
        krahmer_a_xor_mask == 0u) {
        krahmer_snapshot.error_code = -ERANGE;
        PQCLEAN_DILITHIUM2_CLEAN_polyvec_matrix_pointwise_montgomery(
            out,
            mat,
            value);
        return;
    }

    original = mat[row].vec[col].coeffs[coeff];
    faulty =
        (int32_t)((uint32_t)original ^ krahmer_a_xor_mask);

    krahmer_audit.a_original = original;
    krahmer_audit.a_faulty = faulty;

#if KRAHMER_ATTACK_BUILD == 1
    /*
     * The A data fault is injected before the measured consumer starts.
     * No fault selector, XOR, or audit write is counted by the PMU.
     */
    mat[row].vec[col].coeffs[coeff] = faulty;
#endif
    krahmer_compiler_barrier();

    if (krahmer_measurement_enabled && krahmer_hpc_ready) {
        krahmer_hpc_begin_unconditional();
        PQCLEAN_DILITHIUM2_CLEAN_krahmer_matrix_consume(
            out,
            mat,
            value);
        krahmer_hpc_end_unconditional();
    } else {
        PQCLEAN_DILITHIUM2_CLEAN_krahmer_matrix_consume(
            out,
            mat,
            value);
    }

    krahmer_compiler_barrier();
#if KRAHMER_ATTACK_BUILD == 1
    mat[row].vec[col].coeffs[coeff] = original;
#endif

    /*
     * Reference calculation and comparison occur after counters stop.
     * The faulted output remains in *out for the original signing path.
     */
    PQCLEAN_DILITHIUM2_CLEAN_polyvec_matrix_pointwise_montgomery(
        &reference,
        mat,
        value);

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
    krahmer_audit.fault_applied = 0;
    krahmer_audit.semantic_valid =
        krahmer_audit.a_original != krahmer_audit.a_faulty &&
        mismatches == 0u;
#else
    krahmer_audit.fault_applied =
        krahmer_audit.a_original != krahmer_audit.a_faulty &&
        mismatches > 0u;
    krahmer_audit.semantic_valid =
        krahmer_audit.fault_applied;
#endif
}
