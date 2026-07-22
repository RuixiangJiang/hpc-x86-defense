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
#define FIDDLE_HIDDEN __attribute__((visibility("hidden"), used))
#define FIDDLE_ALIGNED_PAGE __attribute__((aligned(4096), used))
#else
#define FIDDLE_NOINLINE
#define FIDDLE_HIDDEN
#define FIDDLE_ALIGNED_PAGE
#endif

#define FIDDLE_CACHE_CONFIG(cache_, op_, result_) \
    ((uint64_t)(cache_) | ((uint64_t)(op_) << 8) | \
     ((uint64_t)(result_) << 16))

typedef struct {
    const char *name;
    uint32_t type;
    uint64_t config;
} fiddle_event_desc;

static const fiddle_event_desc fiddle_structural_events[6] = {
    {"cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES},
    {"instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS},
    {"branches", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS},
    {"branch_misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES},
    {"retired_loads", FIDDLE_TWIDDLE_PMU_TYPE,
     FIDDLE_TWIDDLE_LOAD_CONFIG},
    {"retired_stores", FIDDLE_TWIDDLE_PMU_TYPE,
     FIDDLE_TWIDDLE_STORE_CONFIG},
};

static const fiddle_event_desc fiddle_cache_l1d_events[4] = {
    {"cache_references", PERF_TYPE_HARDWARE,
     PERF_COUNT_HW_CACHE_REFERENCES},
    {"cache_misses", PERF_TYPE_HARDWARE,
     PERF_COUNT_HW_CACHE_MISSES},
    {"l1d_read_accesses", PERF_TYPE_HW_CACHE,
     FIDDLE_CACHE_CONFIG(
         PERF_COUNT_HW_CACHE_L1D,
         PERF_COUNT_HW_CACHE_OP_READ,
         PERF_COUNT_HW_CACHE_RESULT_ACCESS)},
    {"l1d_read_misses", PERF_TYPE_HW_CACHE,
     FIDDLE_CACHE_CONFIG(
         PERF_COUNT_HW_CACHE_L1D,
         PERF_COUNT_HW_CACHE_OP_READ,
         PERF_COUNT_HW_CACHE_RESULT_MISS)},
};

static const fiddle_event_desc fiddle_cache_llc_dtlb_events[4] = {
    {"llc_read_accesses", PERF_TYPE_HW_CACHE,
     FIDDLE_CACHE_CONFIG(
         PERF_COUNT_HW_CACHE_LL,
         PERF_COUNT_HW_CACHE_OP_READ,
         PERF_COUNT_HW_CACHE_RESULT_ACCESS)},
    {"llc_read_misses", PERF_TYPE_HW_CACHE,
     FIDDLE_CACHE_CONFIG(
         PERF_COUNT_HW_CACHE_LL,
         PERF_COUNT_HW_CACHE_OP_READ,
         PERF_COUNT_HW_CACHE_RESULT_MISS)},
    {"dtlb_read_accesses", PERF_TYPE_HW_CACHE,
     FIDDLE_CACHE_CONFIG(
         PERF_COUNT_HW_CACHE_DTLB,
         PERF_COUNT_HW_CACHE_OP_READ,
         PERF_COUNT_HW_CACHE_RESULT_ACCESS)},
    {"dtlb_read_misses", PERF_TYPE_HW_CACHE,
     FIDDLE_CACHE_CONFIG(
         PERF_COUNT_HW_CACHE_DTLB,
         PERF_COUNT_HW_CACHE_OP_READ,
         PERF_COUNT_HW_CACHE_RESULT_MISS)},
};

static const fiddle_event_desc *fiddle_events =
    fiddle_structural_events;
static unsigned int fiddle_active_event_count = 6u;
static unsigned int fiddle_counter_set =
    FIDDLE_COUNTER_SET_STRUCTURAL;

static int fiddle_fds[FIDDLE_TWIDDLE_HPC_MAX_EVENTS] = {
    -1, -1, -1, -1, -1, -1
};
static uint64_t fiddle_ids[FIDDLE_TWIDDLE_HPC_MAX_EVENTS];

static int fiddle_hpc_ready;
static int fiddle_measurement_enabled;

static unsigned int fiddle_mode = FIDDLE_MODE_BASELINE;
static unsigned int fiddle_target_vec;
static uint64_t fiddle_signing_invocations;

static fiddle_twiddle_hpc_snapshot fiddle_snapshot;
static fiddle_twiddle_audit_snapshot fiddle_audit;

/*
 * Condition-2 is prepared outside the PMU window. This page-aligned table is
 * explicitly filled with zero before measurement begins.
 */
static int32_t fiddle_zero_twiddle_table[N] FIDDLE_ALIGNED_PAGE;

/*
 * This is the software analogue of the literal word read by
 *     ldr r1, [pc, #4]
 * on Cortex-M4. Both baseline and attack execute the same RIP-relative MOV
 * at the same instruction address. Only this literal's pre-existing value
 * differs, and it is selected before PMU enable.
 */
const int32_t *fiddle_active_twiddle_pointer_literal FIDDLE_HIDDEN;

static const int32_t *fiddle_correct_twiddle_pointer;
static int fiddle_zero_table_verified;

typedef struct {
    uint64_t value;
    uint64_t id;
} fiddle_read_value;

typedef struct {
    uint64_t nr;
    uint64_t time_enabled;
    uint64_t time_running;
    fiddle_read_value values[FIDDLE_TWIDDLE_HPC_MAX_EVENTS];
} fiddle_group_read;

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

static inline void fiddle_compiler_barrier(void)
{
    __asm__ volatile("" ::: "memory");
}

static void fiddle_close_all(void)
{
    unsigned int i;

    for (i = 0; i < FIDDLE_TWIDDLE_HPC_MAX_EVENTS; ++i) {
        if (fiddle_fds[i] >= 0) {
            close(fiddle_fds[i]);
            fiddle_fds[i] = -1;
        }
        fiddle_ids[i] = 0;
    }

    fiddle_hpc_ready = 0;
}

int PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_set_counter_set(
    unsigned int counter_set)
{
    if (fiddle_hpc_ready) {
        return -EBUSY;
    }

    switch (counter_set) {
    case FIDDLE_COUNTER_SET_STRUCTURAL:
        fiddle_events = fiddle_structural_events;
        fiddle_active_event_count = 6u;
        break;
    case FIDDLE_COUNTER_SET_CACHE_L1D:
        fiddle_events = fiddle_cache_l1d_events;
        fiddle_active_event_count = 4u;
        break;
    case FIDDLE_COUNTER_SET_CACHE_LLC_DTLB:
        fiddle_events = fiddle_cache_llc_dtlb_events;
        fiddle_active_event_count = 4u;
        break;
    default:
        return -EINVAL;
    }

    fiddle_counter_set = counter_set;
    return 0;
}

unsigned int PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_event_count(void)
{
    return fiddle_active_event_count;
}

const char *PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_counter_set_name(void)
{
    switch (fiddle_counter_set) {
    case FIDDLE_COUNTER_SET_STRUCTURAL:
        return "structural";
    case FIDDLE_COUNTER_SET_CACHE_L1D:
        return "cache-l1d";
    case FIDDLE_COUNTER_SET_CACHE_LLC_DTLB:
        return "cache-llc-dtlb";
    default:
        return "invalid";
    }
}

int PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_hpc_init(void)
{
    struct perf_event_attr attr;
    int leader = -1;
    unsigned int i;

    fiddle_close_all();
    memset(&fiddle_snapshot, 0, sizeof(fiddle_snapshot));

    for (i = 0; i < fiddle_active_event_count; ++i) {
        memset(&attr, 0, sizeof(attr));
        attr.size = sizeof(attr);
        attr.type = fiddle_events[i].type;
        attr.config = fiddle_events[i].config;
        attr.disabled = 1;
        attr.exclude_kernel = 1;
        attr.exclude_hv = 1;
        attr.inherit = 0;
        attr.pinned =
            (fiddle_counter_set == FIDDLE_COUNTER_SET_STRUCTURAL &&
             i == 0u)
                ? 1u
                : 0u;
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
    if (index >= fiddle_active_event_count) {
        return "unknown";
    }
    return fiddle_events[index].name;
}

const char *PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_mode_name(void)
{
    return fiddle_mode == FIDDLE_MODE_ATTACK ? "attack" : "baseline";
}

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
    fiddle_snapshot.counter_set = fiddle_counter_set;
    fiddle_snapshot.active_event_count = fiddle_active_event_count;
    fiddle_snapshot.target_vec = fiddle_target_vec;
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

    if (data.nr > fiddle_active_event_count) {
        data.nr = fiddle_active_event_count;
    }

    for (i = 0; i < data.nr; ++i) {
        for (j = 0; j < fiddle_active_event_count; ++j) {
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

static int fiddle_prepare_pointer_literal(unsigned int mode)
{
    unsigned int i;
    volatile int32_t prefault_sink = 0;

    fiddle_correct_twiddle_pointer =
        PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_zetas();

    memset(
        fiddle_zero_twiddle_table,
        0,
        sizeof(fiddle_zero_twiddle_table));

    fiddle_zero_table_verified = 1;
    for (i = 0; i < (unsigned int)N; ++i) {
        if (fiddle_zero_twiddle_table[i] != 0) {
            fiddle_zero_table_verified = 0;
        }
    }

    /*
     * Resolve both pages outside the PMU interval. This avoids counting page
     * faults or table construction as part of the victim window.
     */
    for (i = 0; i < (unsigned int)N; i += 16u) {
        prefault_sink ^= fiddle_correct_twiddle_pointer[i];
        prefault_sink ^= fiddle_zero_twiddle_table[i];
    }
    (void)prefault_sink;

    fiddle_active_twiddle_pointer_literal =
        mode == FIDDLE_MODE_ATTACK
            ? fiddle_zero_twiddle_table
            : fiddle_correct_twiddle_pointer;

    fiddle_compiler_barrier();
    return fiddle_zero_table_verified ? 0 : -EIO;
}

void PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_configure(
    unsigned int mode,
    unsigned int target_vec)
{
    fiddle_mode = mode;
    fiddle_target_vec = target_vec;

    if (mode > FIDDLE_MODE_ATTACK ||
        target_vec >= (unsigned int)L ||
        fiddle_prepare_pointer_literal(mode) != 0) {
        fiddle_snapshot.error_code = -EINVAL;
    }
}

static void fiddle_ntt_with_pointer(
    int32_t a[N],
    const int32_t *twiddle_pointer)
{
    unsigned int len;
    unsigned int start;
    unsigned int j;
    unsigned int k = 0;
    int32_t zeta;
    int32_t t;

    for (len = 128; len > 0; len >>= 1) {
        for (start = 0; start < (unsigned int)N;
             start = j + len) {
            zeta = twiddle_pointer[++k];
            for (j = start; j < start + len; ++j) {
                t = PQCLEAN_DILITHIUM2_CLEAN_montgomery_reduce(
                    (int64_t)zeta * a[j + len]);
                a[j + len] = a[j] - t;
                a[j] = a[j] + t;
            }
        }
    }
}

FIDDLE_NOINLINE
const int32_t *
PQCLEAN_DILITHIUM2_CLEAN_fiddle_ntt_from_pointer_literal(
    int32_t a[N])
{
    const int32_t *twiddle_pointer;

    /*
     * x86-64 analogue of ldr r1, [pc, #4]:
     * one RIP-relative load retrieves T in baseline and T* in attack.
     * The instruction address and opcode are identical in both modes.
     */
    __asm__ volatile(
        ".globl fiddle_twiddle_pointer_load_site\n"
        "fiddle_twiddle_pointer_load_site:\n\t"
        "movq fiddle_active_twiddle_pointer_literal(%%rip), %0\n\t"
        : "=r"(twiddle_pointer)
        :
        : "memory");

    fiddle_ntt_with_pointer(a, twiddle_pointer);
    return twiddle_pointer;
}

static const int32_t *fiddle_run_target_ntt(int32_t a[N])
{
    const int32_t *loaded_pointer;

    if (fiddle_measurement_enabled && fiddle_hpc_ready) {
        fiddle_snapshot.cpu_before = sched_getcpu();
        fiddle_hpc_begin_unconditional();

        /*
         * Expanded victim window:
         * pointer literal load -> all twiddle loads -> complete target NTT.
         */
        loaded_pointer =
            PQCLEAN_DILITHIUM2_CLEAN_fiddle_ntt_from_pointer_literal(a);

        fiddle_hpc_end_unconditional();
        fiddle_snapshot.cpu_after = sched_getcpu();
    } else {
        loaded_pointer =
            PQCLEAN_DILITHIUM2_CLEAN_fiddle_ntt_from_pointer_literal(a);
    }

    return loaded_pointer;
}

static void fiddle_instrumented_ntt(int32_t a[N])
{
    int32_t original_input[N];
    int32_t reference_output[N];
    const int32_t *loaded_pointer;
    unsigned int i;

    memcpy(original_input, a, sizeof(original_input));
    memset(&fiddle_audit, 0, sizeof(fiddle_audit));

    fiddle_audit.mode = fiddle_mode;
    fiddle_audit.target_vec = fiddle_target_vec;
    fiddle_audit.correct_pointer =
        (uint64_t)(uintptr_t)fiddle_correct_twiddle_pointer;
    fiddle_audit.zero_table_pointer =
        (uint64_t)(uintptr_t)fiddle_zero_twiddle_table;
    fiddle_audit.correct_first_twiddle =
        fiddle_correct_twiddle_pointer[1];
    fiddle_audit.zero_table_verified =
        (uint32_t)fiddle_zero_table_verified;
    fiddle_audit.fault_requested =
        fiddle_mode == FIDDLE_MODE_ATTACK;

    loaded_pointer = fiddle_run_target_ntt(a);

    /*
     * Everything below is outside the PMU interval.
     */
    fiddle_audit.loaded_pointer =
        (uint64_t)(uintptr_t)loaded_pointer;
    fiddle_audit.loaded_first_twiddle = loaded_pointer[1];
    fiddle_audit.twiddles_consumed = (unsigned int)N - 1u;
    fiddle_audit.pointer_redirected =
        loaded_pointer != fiddle_correct_twiddle_pointer;

    memcpy(reference_output, original_input, sizeof(reference_output));
    PQCLEAN_DILITHIUM2_CLEAN_ntt(reference_output);

    for (i = 0; i < (unsigned int)N; ++i) {
        if (a[i] != reference_output[i]) {
            fiddle_audit.target_ntt_mismatches++;
        }
    }

    if (fiddle_mode == FIDDLE_MODE_BASELINE) {
        fiddle_audit.fault_applied = 0u;
        fiddle_audit.semantic_valid =
            loaded_pointer == fiddle_correct_twiddle_pointer &&
            fiddle_audit.pointer_redirected == 0u &&
            fiddle_audit.loaded_first_twiddle ==
                fiddle_audit.correct_first_twiddle &&
            fiddle_audit.target_ntt_mismatches == 0u;
    } else {
        fiddle_audit.fault_applied =
            loaded_pointer == fiddle_zero_twiddle_table &&
            fiddle_audit.pointer_redirected == 1u &&
            fiddle_audit.zero_table_verified == 1u &&
            fiddle_audit.loaded_first_twiddle == 0 &&
            fiddle_audit.target_ntt_mismatches > 0u;
        fiddle_audit.semantic_valid =
            fiddle_audit.fault_applied;
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_polyvecl_ntt(
    polyvecl *value)
{
    unsigned int i;

    fiddle_signing_invocations++;

    if (fiddle_target_vec >= (unsigned int)L ||
        fiddle_mode > FIDDLE_MODE_ATTACK ||
        fiddle_active_twiddle_pointer_literal == NULL ||
        fiddle_correct_twiddle_pointer == NULL) {
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
