#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "signature_correction_x86.h"

#include "params.h"

#include <errno.h>
#include <linux/perf_event.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SIGNCORR_PMU_TYPE
#define SIGNCORR_PMU_TYPE 4u
#endif

#ifndef SIGNCORR_LOAD_CONFIG
#define SIGNCORR_LOAD_CONFIG UINT64_C(0x81d0)
#endif

#ifndef SIGNCORR_STORE_CONFIG
#define SIGNCORR_STORE_CONFIG UINT64_C(0x82d0)
#endif

typedef struct {
    const char *name;
    uint32_t type;
    uint64_t config;
} signcorr_event_desc;

static const signcorr_event_desc signcorr_events[
    SIGNCORR_HPC_EVENT_COUNT] = {
    {"cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES},
    {"instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS},
    {"branches", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS},
    {"branch-misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES},
    {"retired-loads", SIGNCORR_PMU_TYPE, SIGNCORR_LOAD_CONFIG},
    {"retired-stores", SIGNCORR_PMU_TYPE, SIGNCORR_STORE_CONFIG},
};

static int signcorr_fds[SIGNCORR_HPC_EVENT_COUNT] = {
    -1, -1, -1, -1, -1, -1
};
static uint64_t signcorr_ids[SIGNCORR_HPC_EVENT_COUNT];

static int signcorr_hpc_ready;
static int signcorr_measurement_enabled;
static int signcorr_fault_enable;
static unsigned int signcorr_target_vec;
static unsigned int signcorr_target_coeff = 17u;
static unsigned int signcorr_bit_index;
static uint64_t signcorr_signing_invocations;

static signcorr_hpc_snapshot signcorr_snapshot;
static signcorr_audit_snapshot signcorr_audit;

static long signcorr_perf_event_open(
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

static void signcorr_close_all(void)
{
    unsigned int i;

    for (i = 0; i < SIGNCORR_HPC_EVENT_COUNT; ++i) {
        if (signcorr_fds[i] >= 0) {
            close(signcorr_fds[i]);
            signcorr_fds[i] = -1;
        }
        signcorr_ids[i] = 0;
    }

    signcorr_hpc_ready = 0;
}

int PQCLEAN_DILITHIUM2_CLEAN_signcorr_hpc_init(void)
{
    struct perf_event_attr attr;
    int leader = -1;
    unsigned int i;

    signcorr_close_all();
    memset(&signcorr_snapshot, 0, sizeof(signcorr_snapshot));

    for (i = 0; i < SIGNCORR_HPC_EVENT_COUNT; ++i) {
        memset(&attr, 0, sizeof(attr));
        attr.size = sizeof(attr);
        attr.type = signcorr_events[i].type;
        attr.config = signcorr_events[i].config;
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

        signcorr_fds[i] = (int)signcorr_perf_event_open(
            &attr,
            0,
            -1,
            leader,
            PERF_FLAG_FD_CLOEXEC);

        if (signcorr_fds[i] < 0) {
            int saved = errno;
            signcorr_close_all();
            signcorr_snapshot.error_code = -saved;
            return -saved;
        }

        if (i == 0u) {
            leader = signcorr_fds[i];
        }

        if (ioctl(
                signcorr_fds[i],
                PERF_EVENT_IOC_ID,
                &signcorr_ids[i]) != 0) {
            int saved = errno;
            signcorr_close_all();
            signcorr_snapshot.error_code = -saved;
            return -saved;
        }
    }

    signcorr_hpc_ready = 1;
    signcorr_snapshot.error_code = 0;
    return 0;
}

void PQCLEAN_DILITHIUM2_CLEAN_signcorr_hpc_close(void)
{
    signcorr_close_all();
}

void PQCLEAN_DILITHIUM2_CLEAN_signcorr_configure(
    int fault_enable,
    unsigned int target_vec,
    unsigned int target_coeff,
    unsigned int bit_index)
{
    signcorr_fault_enable = fault_enable != 0;
    signcorr_target_vec = target_vec;
    signcorr_target_coeff = target_coeff;
    signcorr_bit_index = bit_index;
}

void PQCLEAN_DILITHIUM2_CLEAN_signcorr_set_measurement_enabled(
    int enabled)
{
    signcorr_measurement_enabled = enabled != 0;
}

void PQCLEAN_DILITHIUM2_CLEAN_signcorr_get_hpc_snapshot(
    signcorr_hpc_snapshot *out)
{
    if (out != NULL) {
        *out = signcorr_snapshot;
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_signcorr_get_audit_snapshot(
    signcorr_audit_snapshot *out)
{
    if (out != NULL) {
        *out = signcorr_audit;
    }
}

const char *PQCLEAN_DILITHIUM2_CLEAN_signcorr_event_name(
    unsigned int index)
{
    if (index >= SIGNCORR_HPC_EVENT_COUNT) {
        return "unknown";
    }
    return signcorr_events[index].name;
}

static inline void signcorr_compiler_barrier(void)
{
    __asm__ volatile("" ::: "memory");
}

typedef struct {
    uint64_t value;
    uint64_t id;
} signcorr_read_value;

typedef struct {
    uint64_t nr;
    uint64_t time_enabled;
    uint64_t time_running;
    signcorr_read_value values[SIGNCORR_HPC_EVENT_COUNT];
} signcorr_group_read;

static inline void signcorr_hpc_begin_unconditional(void)
{
    signcorr_snapshot.error_code = 0;
    signcorr_compiler_barrier();

    if (ioctl(
            signcorr_fds[0],
            PERF_EVENT_IOC_RESET,
            PERF_IOC_FLAG_GROUP) != 0) {
        signcorr_snapshot.error_code = -errno;
    }

    if (ioctl(
            signcorr_fds[0],
            PERF_EVENT_IOC_ENABLE,
            PERF_IOC_FLAG_GROUP) != 0) {
        signcorr_snapshot.error_code = -errno;
    }

    signcorr_compiler_barrier();
}

static void signcorr_hpc_end_unconditional(void)
{
    signcorr_group_read data;
    ssize_t got;
    unsigned int i;
    unsigned int j;

    signcorr_compiler_barrier();

    if (ioctl(
            signcorr_fds[0],
            PERF_EVENT_IOC_DISABLE,
            PERF_IOC_FLAG_GROUP) != 0) {
        signcorr_snapshot.error_code = -errno;
    }

    signcorr_compiler_barrier();
    memset(&data, 0, sizeof(data));
    got = read(signcorr_fds[0], &data, sizeof(data));

    signcorr_snapshot.sequence++;
    signcorr_snapshot.signing_invocations =
        signcorr_signing_invocations;
    signcorr_snapshot.target_vec = signcorr_target_vec;
    signcorr_snapshot.target_coeff = signcorr_target_coeff;
    signcorr_snapshot.bit_index = signcorr_bit_index;
    signcorr_snapshot.valid_mask = 0;
    memset(
        signcorr_snapshot.values,
        0,
        sizeof(signcorr_snapshot.values));

    if (got < (ssize_t)(3u * sizeof(uint64_t))) {
        signcorr_snapshot.error_code =
            (got < 0) ? -errno : -EIO;
        return;
    }

    signcorr_snapshot.time_enabled = data.time_enabled;
    signcorr_snapshot.time_running = data.time_running;

    if (data.nr > SIGNCORR_HPC_EVENT_COUNT) {
        data.nr = SIGNCORR_HPC_EVENT_COUNT;
    }

    for (i = 0; i < data.nr; ++i) {
        for (j = 0; j < SIGNCORR_HPC_EVENT_COUNT; ++j) {
            if (data.values[i].id == signcorr_ids[j]) {
                signcorr_snapshot.values[j] =
                    data.values[i].value;
                signcorr_snapshot.valid_mask |=
                    (uint32_t)(1u << j);
                break;
            }
        }
    }
}

static unsigned int signcorr_popcount32(uint32_t value)
{
#if defined(__GNUC__) || defined(__clang__)
    return (unsigned int)__builtin_popcount(value);
#else
    unsigned int count = 0;
    while (value != 0u) {
        value &= value - 1u;
        count++;
    }
    return count;
#endif
}

/*
 * The software simulation reproduces the paper's fault effect:
 *
 *     one bit in one expanded int32_t coefficient of s1 is flipped
 *     after unpacking and before NTT(s1).
 *
 * This function always executes before the PMU target window. The measured
 * victim interval therefore does not include the XOR, fault-mode branch,
 * target selection, or audit writes.
 */
static __attribute__((noinline, noclone, used))
void signcorr_prepare_fault(polyvecl *s1)
{
    int32_t original;
    int32_t faulty;
    uint32_t original_word;
    uint32_t faulty_word;
    uint32_t mask;

    memset(&signcorr_audit, 0, sizeof(signcorr_audit));
    signcorr_audit.target_vec = signcorr_target_vec;
    signcorr_audit.target_coeff = signcorr_target_coeff;
    signcorr_audit.bit_index = signcorr_bit_index;
    signcorr_audit.fault_requested =
        signcorr_fault_enable != 0;

    original =
        s1->vec[signcorr_target_vec]
            .coeffs[signcorr_target_coeff];
    memcpy(&original_word, &original, sizeof(original_word));

    mask = UINT32_C(1) << signcorr_bit_index;
    faulty_word = original_word;

    if (signcorr_fault_enable) {
        faulty_word ^= mask;
    }

    memcpy(&faulty, &faulty_word, sizeof(faulty));

    s1->vec[signcorr_target_vec]
        .coeffs[signcorr_target_coeff] = faulty;

    signcorr_audit.original_value = original;
    signcorr_audit.faulty_value = faulty;
    signcorr_audit.original_word = original_word;
    signcorr_audit.faulty_word = faulty_word;
    signcorr_audit.xor_mask = mask;
    signcorr_audit.original_bit =
        (original_word >> signcorr_bit_index) & 1u;
    signcorr_audit.faulty_bit =
        (faulty_word >> signcorr_bit_index) & 1u;
    signcorr_audit.hamming_distance =
        signcorr_popcount32(original_word ^ faulty_word);
    signcorr_audit.fault_applied =
        original_word != faulty_word;

    signcorr_audit.valid =
        signcorr_fault_enable
            ? (signcorr_audit.hamming_distance == 1u &&
               (original_word ^ faulty_word) == mask)
            : (signcorr_audit.hamming_distance == 0u &&
               original_word == faulty_word);
}

/*
 * This is the complete victim-side PMU target window.
 *
 * It contains only the original Dilithium polyvecl_ntt(&s1) execution plus
 * the unavoidable counter-control calls. It contains no software injection
 * operation and no attack-mode decision.
 */
static __attribute__((noinline, noclone, used))
void signcorr_measure_s1_ntt(polyvecl *s1)
{
    signcorr_hpc_begin_unconditional();
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_ntt(s1);
    signcorr_hpc_end_unconditional();
}

void PQCLEAN_DILITHIUM2_CLEAN_signcorr_prepare_and_measure_s1(
    polyvecl *s1)
{
    signcorr_signing_invocations++;

    if (signcorr_target_vec >= (unsigned int)L ||
        signcorr_target_coeff >= (unsigned int)N ||
        signcorr_bit_index >= 32u) {
        memset(&signcorr_audit, 0, sizeof(signcorr_audit));
        signcorr_snapshot.error_code = -ERANGE;
        PQCLEAN_DILITHIUM2_CLEAN_polyvecl_ntt(s1);
        return;
    }

    signcorr_prepare_fault(s1);

    if (signcorr_measurement_enabled && signcorr_hpc_ready) {
        signcorr_measure_s1_ntt(s1);
        return;
    }

    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_ntt(s1);
}
