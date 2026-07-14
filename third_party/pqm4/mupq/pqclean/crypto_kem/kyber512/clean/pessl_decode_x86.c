#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "pessl_decode_x86.h"

#include <errno.h>
#include <linux/perf_event.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef PESSL_DECODE_BUILD_MODE
#error "PESSL_DECODE_BUILD_MODE must be defined at compile time"
#endif

#if PESSL_DECODE_BUILD_MODE != PESSL_DECODE_MODE_BASELINE && \
    PESSL_DECODE_BUILD_MODE != PESSL_DECODE_MODE_SKIP_SHIFT
#error "invalid PESSL_DECODE_BUILD_MODE"
#endif

#ifndef PESSL_PMU_TYPE
#define PESSL_PMU_TYPE 4u
#endif

#ifndef PESSL_LOAD_CONFIG
#define PESSL_LOAD_CONFIG UINT64_C(0x81d0)
#endif

#ifndef PESSL_STORE_CONFIG
#define PESSL_STORE_CONFIG UINT64_C(0x82d0)
#endif

typedef struct {
    const char *name;
    uint32_t type;
    uint64_t config;
} pessl_event_desc;

static const pessl_event_desc pessl_events[
    PESSL_DECODE_HPC_EVENT_COUNT] = {
    {"cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES},
    {"instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS},
    {"branches", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS},
    {"branch-misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES},
    {"retired-loads", PESSL_PMU_TYPE, PESSL_LOAD_CONFIG},
    {"retired-stores", PESSL_PMU_TYPE, PESSL_STORE_CONFIG},
};

static int pessl_fds[PESSL_DECODE_HPC_EVENT_COUNT] = {
    -1, -1, -1, -1, -1, -1
};
static uint64_t pessl_ids[PESSL_DECODE_HPC_EVENT_COUNT];
static int pessl_hpc_ready;
static int pessl_measurement_enabled;
static unsigned int pessl_target_coeff;
static uint64_t pessl_decode_invocations;
static pessl_decode_hpc_snapshot pessl_snapshot;
static pessl_decode_audit_snapshot pessl_audit;

static long pessl_perf_event_open(struct perf_event_attr *attr,
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

static void pessl_close_all(void)
{
    unsigned int i;

    for (i = 0; i < PESSL_DECODE_HPC_EVENT_COUNT; ++i) {
        if (pessl_fds[i] >= 0) {
            close(pessl_fds[i]);
            pessl_fds[i] = -1;
        }
        pessl_ids[i] = 0;
    }

    pessl_hpc_ready = 0;
}

int PQCLEAN_KYBER512_CLEAN_pessl_decode_hpc_init(void)
{
    struct perf_event_attr attr;
    int leader = -1;
    unsigned int i;

    pessl_close_all();
    memset(&pessl_snapshot, 0, sizeof(pessl_snapshot));

    for (i = 0; i < PESSL_DECODE_HPC_EVENT_COUNT; ++i) {
        memset(&attr, 0, sizeof(attr));
        attr.size = sizeof(attr);
        attr.type = pessl_events[i].type;
        attr.config = pessl_events[i].config;
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

        pessl_fds[i] = (int)pessl_perf_event_open(
            &attr,
            0,
            -1,
            leader,
            PERF_FLAG_FD_CLOEXEC);

        if (pessl_fds[i] < 0) {
            int saved = errno;
            pessl_close_all();
            pessl_snapshot.error_code = -saved;
            return -saved;
        }

        if (i == 0u) {
            leader = pessl_fds[i];
        }

        if (ioctl(pessl_fds[i],
                  PERF_EVENT_IOC_ID,
                  &pessl_ids[i]) != 0) {
            int saved = errno;
            pessl_close_all();
            pessl_snapshot.error_code = -saved;
            return -saved;
        }
    }

    pessl_hpc_ready = 1;
    pessl_snapshot.error_code = 0;
    return 0;
}

void PQCLEAN_KYBER512_CLEAN_pessl_decode_hpc_close(void)
{
    pessl_close_all();
}

void PQCLEAN_KYBER512_CLEAN_pessl_decode_set_target(
    unsigned int target_coeff)
{
    pessl_target_coeff = target_coeff;
}

void PQCLEAN_KYBER512_CLEAN_pessl_decode_set_measurement_enabled(
    int enabled)
{
    pessl_measurement_enabled = enabled != 0;
}

void PQCLEAN_KYBER512_CLEAN_pessl_decode_get_hpc_snapshot(
    pessl_decode_hpc_snapshot *out)
{
    if (out != NULL) {
        *out = pessl_snapshot;
    }
}

void PQCLEAN_KYBER512_CLEAN_pessl_decode_get_audit_snapshot(
    pessl_decode_audit_snapshot *out)
{
    if (out != NULL) {
        *out = pessl_audit;
    }
}

int PQCLEAN_KYBER512_CLEAN_pessl_decode_build_mode(void)
{
    return PESSL_DECODE_BUILD_MODE;
}

const char *PQCLEAN_KYBER512_CLEAN_pessl_decode_mode_name(void)
{
#if PESSL_DECODE_BUILD_MODE == PESSL_DECODE_MODE_BASELINE
    return "baseline";
#else
    return "skip-shift";
#endif
}

const char *PQCLEAN_KYBER512_CLEAN_pessl_decode_event_name(
    unsigned int index)
{
    if (index >= PESSL_DECODE_HPC_EVENT_COUNT) {
        return "unknown";
    }
    return pessl_events[index].name;
}

static inline void pessl_compiler_barrier(void)
{
    __asm__ volatile("" ::: "memory");
}

typedef struct {
    uint64_t value;
    uint64_t id;
} pessl_read_value;

typedef struct {
    uint64_t nr;
    uint64_t time_enabled;
    uint64_t time_running;
    pessl_read_value values[PESSL_DECODE_HPC_EVENT_COUNT];
} pessl_group_read;

static inline void pessl_hpc_begin_unconditional(void)
{
    pessl_snapshot.error_code = 0;
    pessl_compiler_barrier();

    if (ioctl(pessl_fds[0],
              PERF_EVENT_IOC_RESET,
              PERF_IOC_FLAG_GROUP) != 0) {
        pessl_snapshot.error_code = -errno;
    }

    if (ioctl(pessl_fds[0],
              PERF_EVENT_IOC_ENABLE,
              PERF_IOC_FLAG_GROUP) != 0) {
        pessl_snapshot.error_code = -errno;
    }

    pessl_compiler_barrier();
}

static void pessl_hpc_end_unconditional(void)
{
    pessl_group_read data;
    ssize_t got;
    unsigned int i;
    unsigned int j;

    pessl_compiler_barrier();

    if (ioctl(pessl_fds[0],
              PERF_EVENT_IOC_DISABLE,
              PERF_IOC_FLAG_GROUP) != 0) {
        pessl_snapshot.error_code = -errno;
    }

    pessl_compiler_barrier();
    memset(&data, 0, sizeof(data));
    got = read(pessl_fds[0], &data, sizeof(data));

    pessl_snapshot.sequence++;
    pessl_snapshot.decode_invocations = pessl_decode_invocations;
    pessl_snapshot.target_coeff = pessl_target_coeff;
    pessl_snapshot.valid_mask = 0;
    memset(pessl_snapshot.values,
           0,
           sizeof(pessl_snapshot.values));

    if (got < (ssize_t)(3u * sizeof(uint64_t))) {
        pessl_snapshot.error_code =
            (got < 0) ? -errno : -EIO;
        return;
    }

    pessl_snapshot.time_enabled = data.time_enabled;
    pessl_snapshot.time_running = data.time_running;

    if (data.nr > PESSL_DECODE_HPC_EVENT_COUNT) {
        data.nr = PESSL_DECODE_HPC_EVENT_COUNT;
    }

    for (i = 0; i < data.nr; ++i) {
        for (j = 0; j < PESSL_DECODE_HPC_EVENT_COUNT; ++j) {
            if (data.values[i].id == pessl_ids[j]) {
                pessl_snapshot.values[j] =
                    data.values[i].value;
                pessl_snapshot.valid_mask |=
                    (uint32_t)(1u << j);
                break;
            }
        }
    }
}

static inline uint16_t pessl_normalize_coefficient(int16_t raw)
{
    uint16_t t = (uint16_t)raw;
    t += (uint16_t)(((int16_t)t >> 15) & KYBER_Q);
    return t;
}

static inline uint16_t pessl_decode_bit_normal(uint16_t t)
{
    return (uint16_t)((((t << 1) + KYBER_Q / 2) /
                       KYBER_Q) & 1u);
}

/*
 * Exact software fault used by the public implementation accompanying
 * Pessl and Prokop:
 *
 *     normal: (((t << 1) + q/2) / q) & 1
 *     fault:  (( t       + q/2) / q) & 1
 *
 * The fault skips the left shift/doubling operation. It does not skip q/2.
 * The target-only HPC window below forces this shift to remain one real
 * retired instruction in the baseline binary.
 */
static inline uint16_t pessl_decode_bit_skip_shift(uint16_t t)
{
    return (uint16_t)(((t + KYBER_Q / 2) /
                       KYBER_Q) & 1u);
}

static inline __attribute__((always_inline))
void pessl_decode_one_normal(uint8_t *msg_byte,
                             unsigned int bit_index,
                             const int16_t *coefficient)
{
    uint16_t t = pessl_normalize_coefficient(*coefficient);
    uint16_t bit = pessl_decode_bit_normal(t);
    *msg_byte |= (uint8_t)(bit << bit_index);
}

/*
 * The attacked operation is kept as one explicit machine instruction.
 *
 * This is more faithful to an instruction-skip simulation than allowing the
 * compiler to fold the source-level shift into a strength-reduced constant
 * division sequence.
 */
static __attribute__((noinline, noclone, used))
uint32_t pessl_target_shift_baseline(uint32_t value)
{
    __asm__ volatile("shll $1, %0"
                     : "+r"(value)
                     :
                     : "cc");
    return value;
}

/*
 * Exact skip fault: the baseline shl instruction is absent.
 *
 * The empty asm emits no machine instruction. It is only a compiler boundary
 * that keeps the input/output register relationship comparable.
 */
static __attribute__((noinline, noclone, used))
uint32_t pessl_target_shift_skip(uint32_t value)
{
    __asm__ volatile(""
                     : "+r"(value)
                     :
                     : "cc");
    return value;
}

static inline __attribute__((always_inline))
uint32_t pessl_target_shift_selected(uint32_t value)
{
#if PESSL_DECODE_BUILD_MODE == PESSL_DECODE_MODE_BASELINE
    return pessl_target_shift_baseline(value);
#else
    return pessl_target_shift_skip(value);
#endif
}


static void pessl_decode_all_normal(
    uint8_t msg[KYBER_INDCPA_MSGBYTES],
    const poly *a)
{
    unsigned int flat;

    memset(msg, 0, KYBER_INDCPA_MSGBYTES);
    for (flat = 0; flat < (unsigned int)KYBER_N; ++flat) {
        pessl_decode_one_normal(
            &msg[flat >> 3],
            flat & 7u,
            &a->coeffs[flat]);
    }
}

void PQCLEAN_KYBER512_CLEAN_pessl_decode_apply(
    uint8_t msg[KYBER_INDCPA_MSGBYTES],
    const poly *a)
{
    unsigned int flat;
    unsigned int target = pessl_target_coeff;
    uint8_t *target_byte;
    unsigned int target_bit_index;
    const int16_t *target_coefficient;
    int16_t raw;
    uint16_t normalized;
    uint16_t normal_bit;
    uint16_t fault_bit;

    pessl_decode_invocations++;

    /*
     * All validation and target-address calculation occurs before counters
     * are enabled.
     */
    if (target >= (unsigned int)KYBER_N) {
        pessl_decode_all_normal(msg, a);
        pessl_snapshot.error_code = -ERANGE;
        memset(&pessl_audit, 0, sizeof(pessl_audit));
        return;
    }

    memset(msg, 0, KYBER_INDCPA_MSGBYTES);

    /*
     * Prefix is decoded normally while counters are disabled.
     */
    for (flat = 0; flat < target; ++flat) {
        pessl_decode_one_normal(
            &msg[flat >> 3],
            flat & 7u,
            &a->coeffs[flat]);
    }

    target_byte = &msg[target >> 3];
    target_bit_index = target & 7u;
    target_coefficient = &a->coeffs[target];

    /*
     * Semantic reference values are computed before the monitored window.
     * They are only used for audit and never select the target operation.
     */
    raw = *target_coefficient;
    normalized = pessl_normalize_coefficient(raw);
    normal_bit = pessl_decode_bit_normal(normalized);
    fault_bit = pessl_decode_bit_skip_shift(normalized);

    {
        uint32_t transformed;

        if (pessl_measurement_enabled && pessl_hpc_ready) {
            /*
             * The enabled interval contains only the attacked shift
             * instruction, or its absence in the fault binary.
             */
            pessl_hpc_begin_unconditional();
            transformed =
                pessl_target_shift_selected((uint32_t)normalized);
            pessl_hpc_end_unconditional();
        } else {
            transformed =
                pessl_target_shift_selected((uint32_t)normalized);
        }

        /*
         * The remainder of the original DecodeMessage formula executes
         * normally after the counters are disabled.
         */
        {
            uint16_t observed_bit =
                (uint16_t)((((transformed + KYBER_Q / 2) /
                              KYBER_Q)) & 1u);
            *target_byte |=
                (uint8_t)(observed_bit << target_bit_index);
        }
    }

    /*
     * Audit writes occur after the counters have been disabled.
     */
    pessl_audit.raw_coefficient = raw;
    pessl_audit.normalized_coefficient = normalized;
    pessl_audit.normal_bit = normal_bit;
    pessl_audit.fault_bit = fault_bit;
    pessl_audit.observed_bit =
        (uint32_t)((*target_byte >> target_bit_index) & 1u);
    pessl_audit.target_coeff = target;
    pessl_audit.valid = 1;

    /*
     * Suffix is decoded normally while counters are disabled.
     */
    for (flat = target + 1u;
         flat < (unsigned int)KYBER_N;
         ++flat) {
        pessl_decode_one_normal(
            &msg[flat >> 3],
            flat & 7u,
            &a->coeffs[flat]);
    }
}
