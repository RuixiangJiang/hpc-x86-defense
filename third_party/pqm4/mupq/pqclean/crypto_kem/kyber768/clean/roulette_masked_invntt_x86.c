#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "roulette_masked_invntt_x86.h"

#include "ntt.h"
#include "reduce.h"

#include <errno.h>
#include <limits.h>
#include <linux/perf_event.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef ROULETTE_BUILD_MODE
#error "ROULETTE_BUILD_MODE must be defined at compile time"
#endif

#if ROULETTE_BUILD_MODE != ROULETTE_MODE_BASELINE && \
    ROULETTE_BUILD_MODE != ROULETTE_MODE_SKIP_ADD
#error "invalid ROULETTE_BUILD_MODE"
#endif

#ifndef ROULETTE_PMU_TYPE
#define ROULETTE_PMU_TYPE 4u
#endif

#ifndef ROULETTE_LOAD_CONFIG
#define ROULETTE_LOAD_CONFIG UINT64_C(0x81d0)
#endif

#ifndef ROULETTE_STORE_CONFIG
#define ROULETTE_STORE_CONFIG UINT64_C(0x82d0)
#endif

typedef struct {
    const char *name;
    uint32_t type;
    uint64_t config;
} roulette_event_desc;

static const roulette_event_desc roulette_events[
    ROULETTE_HPC_EVENT_COUNT] = {
    {"cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES},
    {"instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS},
    {"branches", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS},
    {"branch-misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES},
    {"retired-loads", ROULETTE_PMU_TYPE, ROULETTE_LOAD_CONFIG},
    {"retired-stores", ROULETTE_PMU_TYPE, ROULETTE_STORE_CONFIG},
};

static int roulette_fds[ROULETTE_HPC_EVENT_COUNT] = {
    -1, -1, -1, -1, -1, -1
};
static uint64_t roulette_ids[ROULETTE_HPC_EVENT_COUNT];

static int roulette_hpc_ready;
static int roulette_measurement_enabled;
static int roulette_reencrypt_active;
static unsigned int roulette_target_coeff = 17u;
static uint32_t roulette_mask_prng_state = UINT32_C(0x6d2b79f5);
static uint64_t roulette_reencrypt_invocations;

static roulette_hpc_snapshot roulette_snapshot;
static roulette_audit_snapshot roulette_audit;

static long roulette_perf_event_open(
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

static void roulette_close_all(void)
{
    unsigned int i;

    for (i = 0; i < ROULETTE_HPC_EVENT_COUNT; ++i) {
        if (roulette_fds[i] >= 0) {
            close(roulette_fds[i]);
            roulette_fds[i] = -1;
        }
        roulette_ids[i] = 0;
    }

    roulette_hpc_ready = 0;
}

int PQCLEAN_KYBER768_CLEAN_roulette_hpc_init(void)
{
    struct perf_event_attr attr;
    int leader = -1;
    unsigned int i;

    roulette_close_all();
    memset(&roulette_snapshot, 0, sizeof(roulette_snapshot));

    for (i = 0; i < ROULETTE_HPC_EVENT_COUNT; ++i) {
        memset(&attr, 0, sizeof(attr));
        attr.size = sizeof(attr);
        attr.type = roulette_events[i].type;
        attr.config = roulette_events[i].config;
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

        roulette_fds[i] = (int)roulette_perf_event_open(
            &attr,
            0,
            -1,
            leader,
            PERF_FLAG_FD_CLOEXEC);

        if (roulette_fds[i] < 0) {
            int saved = errno;
            roulette_close_all();
            roulette_snapshot.error_code = -saved;
            return -saved;
        }

        if (i == 0u) {
            leader = roulette_fds[i];
        }

        if (ioctl(
                roulette_fds[i],
                PERF_EVENT_IOC_ID,
                &roulette_ids[i]) != 0) {
            int saved = errno;
            roulette_close_all();
            roulette_snapshot.error_code = -saved;
            return -saved;
        }
    }

    roulette_hpc_ready = 1;
    roulette_snapshot.error_code = 0;
    return 0;
}

void PQCLEAN_KYBER768_CLEAN_roulette_hpc_close(void)
{
    roulette_close_all();
}

void PQCLEAN_KYBER768_CLEAN_roulette_set_target(
    unsigned int target_coeff)
{
    roulette_target_coeff = target_coeff;
}

void PQCLEAN_KYBER768_CLEAN_roulette_set_measurement_enabled(
    int enabled)
{
    roulette_measurement_enabled = enabled != 0;
}

void PQCLEAN_KYBER768_CLEAN_roulette_set_reencrypt_active(
    int active)
{
    roulette_reencrypt_active = active != 0;
}

void PQCLEAN_KYBER768_CLEAN_roulette_set_mask_seed(
    uint32_t seed)
{
    roulette_mask_prng_state =
        seed != 0u ? seed : UINT32_C(0x6d2b79f5);
}

void PQCLEAN_KYBER768_CLEAN_roulette_get_hpc_snapshot(
    roulette_hpc_snapshot *out)
{
    if (out != NULL) {
        *out = roulette_snapshot;
    }
}

void PQCLEAN_KYBER768_CLEAN_roulette_get_audit_snapshot(
    roulette_audit_snapshot *out)
{
    if (out != NULL) {
        *out = roulette_audit;
    }
}

int PQCLEAN_KYBER768_CLEAN_roulette_build_mode(void)
{
    return ROULETTE_BUILD_MODE;
}

const char *PQCLEAN_KYBER768_CLEAN_roulette_mode_name(void)
{
#if ROULETTE_BUILD_MODE == ROULETTE_MODE_BASELINE
    return "baseline";
#else
    return "skip-add";
#endif
}

const char *PQCLEAN_KYBER768_CLEAN_roulette_event_name(
    unsigned int index)
{
    if (index >= ROULETTE_HPC_EVENT_COUNT) {
        return "unknown";
    }
    return roulette_events[index].name;
}

static inline void roulette_compiler_barrier(void)
{
    __asm__ volatile("" ::: "memory");
}

typedef struct {
    uint64_t value;
    uint64_t id;
} roulette_read_value;

typedef struct {
    uint64_t nr;
    uint64_t time_enabled;
    uint64_t time_running;
    roulette_read_value values[ROULETTE_HPC_EVENT_COUNT];
} roulette_group_read;

static inline void roulette_hpc_begin_unconditional(void)
{
    roulette_snapshot.error_code = 0;
    roulette_compiler_barrier();

    if (ioctl(
            roulette_fds[0],
            PERF_EVENT_IOC_RESET,
            PERF_IOC_FLAG_GROUP) != 0) {
        roulette_snapshot.error_code = -errno;
    }

    if (ioctl(
            roulette_fds[0],
            PERF_EVENT_IOC_ENABLE,
            PERF_IOC_FLAG_GROUP) != 0) {
        roulette_snapshot.error_code = -errno;
    }

    roulette_compiler_barrier();
}

static void roulette_hpc_end_unconditional(void)
{
    roulette_group_read data;
    ssize_t got;
    unsigned int i;
    unsigned int j;

    roulette_compiler_barrier();

    if (ioctl(
            roulette_fds[0],
            PERF_EVENT_IOC_DISABLE,
            PERF_IOC_FLAG_GROUP) != 0) {
        roulette_snapshot.error_code = -errno;
    }

    roulette_compiler_barrier();
    memset(&data, 0, sizeof(data));
    got = read(roulette_fds[0], &data, sizeof(data));

    roulette_snapshot.sequence++;
    roulette_snapshot.reencrypt_invocations =
        roulette_reencrypt_invocations;
    roulette_snapshot.target_coeff = roulette_target_coeff;
    roulette_snapshot.valid_mask = 0;
    memset(
        roulette_snapshot.values,
        0,
        sizeof(roulette_snapshot.values));

    if (got < (ssize_t)(3u * sizeof(uint64_t))) {
        roulette_snapshot.error_code =
            (got < 0) ? -errno : -EIO;
        return;
    }

    roulette_snapshot.time_enabled = data.time_enabled;
    roulette_snapshot.time_running = data.time_running;

    if (data.nr > ROULETTE_HPC_EVENT_COUNT) {
        data.nr = ROULETTE_HPC_EVENT_COUNT;
    }

    for (i = 0; i < data.nr; ++i) {
        for (j = 0; j < ROULETTE_HPC_EVENT_COUNT; ++j) {
            if (data.values[i].id == roulette_ids[j]) {
                roulette_snapshot.values[j] =
                    data.values[i].value;
                roulette_snapshot.valid_mask |=
                    (uint32_t)(1u << j);
                break;
            }
        }
    }
}

static int32_t roulette_mod_q(int32_t value)
{
    value %= KYBER_Q;
    if (value < 0) {
        value += KYBER_Q;
    }
    return value;
}

static uint32_t roulette_xorshift32(void)
{
    uint32_t x = roulette_mask_prng_state;

    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;

    roulette_mask_prng_state =
        x != 0u ? x : UINT32_C(0x6d2b79f5);
    return roulette_mask_prng_state;
}

static int16_t roulette_uniform_mod_q(void)
{
    const uint64_t range = UINT64_C(1) << 32;
    const uint64_t limit =
        (range / (uint64_t)KYBER_Q) * (uint64_t)KYBER_Q;
    uint32_t value;

    do {
        value = roulette_xorshift32();
    } while ((uint64_t)value >= limit);

    return (int16_t)(value % (uint32_t)KYBER_Q);
}

static int16_t roulette_fqmul(int16_t a, int16_t b)
{
    return PQCLEAN_KYBER768_CLEAN_montgomery_reduce(
        (int32_t)a * b);
}

/*
 * Paper/Table-4 baseline operation:
 *     one arithmetic-masked share executes c_share = a_share + b_share
 *
 * The explicit assembly keeps the attacked operation as one real x86
 * retired instruction. Reduction, mask generation, target selection,
 * auditing, and all later Kyber operations are outside the PMU window.
 */
static __attribute__((noinline, noclone, used))
int32_t roulette_target_share_add_baseline(
    int32_t a_share,
    int32_t b_share)
{
    __asm__ volatile(
        "addl %1, %0"
        : "+r"(a_share)
        : "r"(b_share)
        : "cc");
    return a_share;
}

/*
 * Exact instruction-skip variant of the operation above.
 *
 * No replacement arithmetic, NOP, branch, random draw, or software fault flag
 * is executed in the target primitive. The stale a_share is returned, exactly
 * modeling the missing addition on one share.
 */
static __attribute__((noinline, noclone, used))
int32_t roulette_target_share_add_skip(
    int32_t a_share,
    int32_t b_share)
{
    __asm__ volatile(
        ""
        : "+r"(a_share)
        : "r"(b_share)
        : "cc");
    return a_share;
}

static inline __attribute__((always_inline))
int32_t roulette_target_share_add_selected(
    int32_t a_share,
    int32_t b_share)
{
#if ROULETTE_BUILD_MODE == ROULETTE_MODE_BASELINE
    return roulette_target_share_add_baseline(
        a_share,
        b_share);
#else
    return roulette_target_share_add_skip(
        a_share,
        b_share);
#endif
}

static uint8_t roulette_v_symbol(
    const uint8_t ct[KYBER_CIPHERTEXTBYTES],
    unsigned int target)
{
    size_t byte_offset =
        (size_t)KYBER_POLYVECCOMPRESSEDBYTES +
        (size_t)(target >> 1);
    unsigned int shift = (target & 1u) * 4u;

    return (uint8_t)((ct[byte_offset] >> shift) & 0x0fu);
}

void PQCLEAN_KYBER768_CLEAN_roulette_record_compare(
    const uint8_t input_ct[KYBER_CIPHERTEXTBYTES],
    const uint8_t reencrypted_ct[KYBER_CIPHERTEXTBYTES],
    int compare_fail)
{
    unsigned int target = roulette_target_coeff;

    if (target >= 128u) {
        return;
    }

    roulette_audit.input_v_symbol =
        roulette_v_symbol(input_ct, target);
    roulette_audit.reencrypted_v_symbol =
        roulette_v_symbol(reencrypted_ct, target);
    roulette_audit.target_symbol_match =
        roulette_audit.input_v_symbol ==
        roulette_audit.reencrypted_v_symbol;
    roulette_audit.compare_fail = compare_fail != 0;
    roulette_audit.oracle_success = compare_fail == 0;
    roulette_audit.compare_recorded = 1;
}

void PQCLEAN_KYBER768_CLEAN_roulette_masked_invntt_apply(
    poly *v)
{
    poly reference;
    int16_t share0[KYBER_N];
    int16_t share1[KYBER_N];
    unsigned int target = roulette_target_coeff;
    unsigned int start;
    unsigned int len;
    unsigned int j;
    unsigned int k;
    unsigned int mismatch_count = 0;
    int target_seen = 0;
    const int16_t f = 1441;

    if (!roulette_reencrypt_active) {
        PQCLEAN_KYBER768_CLEAN_poly_invntt_tomont(v);
        return;
    }

    roulette_reencrypt_invocations++;
    memset(&roulette_audit, 0, sizeof(roulette_audit));
    roulette_audit.target_coeff = target;
#if ROULETTE_BUILD_MODE == ROULETTE_MODE_SKIP_ADD
    roulette_audit.operation_skipped = 1;
#endif

    if (target >= 128u) {
        roulette_snapshot.error_code = -ERANGE;
        PQCLEAN_KYBER768_CLEAN_poly_invntt_tomont(v);
        return;
    }

    /*
     * Independent semantic reference. It is computed while counters are off.
     */
    reference = *v;
    PQCLEAN_KYBER768_CLEAN_poly_invntt_tomont(&reference);

    /*
     * First-order arithmetic masking in Z_q:
     *     v = share0 + share1 mod q
     *
     * Exact rejection sampling avoids modulo bias. All random draws and the
     * full mask split are completed before the target PMU window begins.
     */
    for (j = 0; j < KYBER_N; ++j) {
        int32_t value = roulette_mod_q(v->coeffs[j]);
        int16_t random_share = roulette_uniform_mod_q();

        share0[j] = random_share;
        share1[j] = (int16_t)roulette_mod_q(
            value - (int32_t)random_share);
    }

    /*
     * Share-wise inverse NTT. Because the transform is linear, recombining
     * both shares yields the normal result modulo q unless the selected
     * share operation is skipped.
     */
    k = 127u;
    for (len = 2u; len <= 128u; len <<= 1) {
        for (start = 0u; start < KYBER_N; start = j + len) {
            int16_t zeta =
                PQCLEAN_KYBER768_CLEAN_zetas[k--];

            for (j = start; j < start + len; ++j) {
                int16_t a0 = share0[j];
                int16_t b0 = share0[j + len];
                int16_t a1 = share1[j];
                int16_t b1 = share1[j + len];

                if (len == 128u && j == target) {
                    int32_t used_sum;

                    roulette_audit.share_a_before = a0;
                    roulette_audit.share_b_before = b0;
                    roulette_audit.share_normal_sum =
                        (int32_t)a0 + (int32_t)b0;

                    /*
                     * All control decisions occur before counters are enabled.
                     * The interval contains only a direct call to the
                     * compile-time-selected add or skipped-add primitive.
                     */
                    if (roulette_measurement_enabled &&
                        roulette_hpc_ready) {
                        roulette_hpc_begin_unconditional();
                        used_sum =
                            roulette_target_share_add_selected(
                                a0,
                                b0);
                        roulette_hpc_end_unconditional();
                    } else {
                        used_sum =
                            roulette_target_share_add_selected(
                                a0,
                                b0);
                    }

                    roulette_audit.share_used_sum = used_sum;
                    share0[j] =
                        PQCLEAN_KYBER768_CLEAN_barrett_reduce(
                            (int16_t)used_sum);
                    target_seen = 1;
                } else {
                    share0[j] =
                        PQCLEAN_KYBER768_CLEAN_barrett_reduce(
                            (int16_t)((int32_t)a0 + b0));
                }

                share0[j + len] =
                    roulette_fqmul(
                        zeta,
                        (int16_t)((int32_t)b0 - a0));

                share1[j] =
                    PQCLEAN_KYBER768_CLEAN_barrett_reduce(
                        (int16_t)((int32_t)a1 + b1));
                share1[j + len] =
                    roulette_fqmul(
                        zeta,
                        (int16_t)((int32_t)b1 - a1));
            }
        }
    }

    for (j = 0; j < KYBER_N; ++j) {
        share0[j] = roulette_fqmul(share0[j], f);
        share1[j] = roulette_fqmul(share1[j], f);

        v->coeffs[j] =
            PQCLEAN_KYBER768_CLEAN_barrett_reduce(
                (int16_t)((int32_t)share0[j] + share1[j]));
    }

    roulette_audit.reference_coeff_mod_q =
        roulette_mod_q(reference.coeffs[target]);
    roulette_audit.observed_coeff_mod_q =
        roulette_mod_q(v->coeffs[target]);
    roulette_audit.target_changed =
        roulette_audit.reference_coeff_mod_q !=
        roulette_audit.observed_coeff_mod_q;

    for (j = 0; j < KYBER_N; ++j) {
        if (j == target) {
            continue;
        }
        if (roulette_mod_q(reference.coeffs[j]) !=
            roulette_mod_q(v->coeffs[j])) {
            mismatch_count++;
        }
    }

    roulette_audit.non_target_mismatches = mismatch_count;

#if ROULETTE_BUILD_MODE == ROULETTE_MODE_BASELINE
    roulette_audit.valid =
        target_seen &&
        mismatch_count == 0u &&
        roulette_audit.share_used_sum ==
            roulette_audit.share_normal_sum &&
        roulette_audit.reference_coeff_mod_q ==
            roulette_audit.observed_coeff_mod_q;
#else
    roulette_audit.valid =
        target_seen &&
        mismatch_count == 0u &&
        roulette_audit.share_used_sum ==
            roulette_audit.share_a_before;
#endif
}
