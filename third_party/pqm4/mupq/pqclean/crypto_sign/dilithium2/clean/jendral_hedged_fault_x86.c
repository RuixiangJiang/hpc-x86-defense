#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "jendral_hedged_fault_x86.h"

#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "randombytes.h"

#include <errno.h>
#include <linux/perf_event.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef JENDRAL_ATTACK_BUILD
#define JENDRAL_ATTACK_BUILD 0
#endif

#if JENDRAL_ATTACK_BUILD != 0 && JENDRAL_ATTACK_BUILD != 1
#error "JENDRAL_ATTACK_BUILD must be 0 or 1"
#endif

#ifndef JENDRAL_PMU_TYPE
#define JENDRAL_PMU_TYPE 4u
#endif
#ifndef JENDRAL_LOAD_CONFIG
#define JENDRAL_LOAD_CONFIG UINT64_C(0x81d0)
#endif
#ifndef JENDRAL_STORE_CONFIG
#define JENDRAL_STORE_CONFIG UINT64_C(0x82d0)
#endif

#if defined(__GNUC__) || defined(__clang__)
#define JENDRAL_NOINLINE __attribute__((noinline, noclone, used))
#else
#define JENDRAL_NOINLINE
#endif

typedef struct {
    const char *name;
    uint32_t type;
    uint64_t config;
} jendral_event_desc;

static const jendral_event_desc jendral_events[JENDRAL_HPC_EVENT_COUNT] = {
    {"cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES},
    {"instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS},
    {"branches", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS},
    {"branch_misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES},
    {"retired_loads", JENDRAL_PMU_TYPE, JENDRAL_LOAD_CONFIG},
    {"retired_stores", JENDRAL_PMU_TYPE, JENDRAL_STORE_CONFIG},
};

static int jendral_fds[JENDRAL_HPC_EVENT_COUNT] = {-1, -1, -1, -1, -1, -1};
static uint64_t jendral_ids[JENDRAL_HPC_EVENT_COUNT];
static int jendral_hpc_ready;
static int jendral_measurement_enabled;
static uint8_t jendral_public_rnd[SEEDBYTES];
static int jendral_public_rnd_configured;
static uint8_t jendral_used_rhoprime[CRHBYTES];
static uint16_t jendral_final_nonce;
static uint64_t jendral_target_invocations;
static jendral_hpc_snapshot jendral_snapshot;
static jendral_audit_snapshot jendral_audit;

static long jendral_perf_event_open(
    struct perf_event_attr *attr,
    pid_t pid,
    int cpu,
    int group_fd,
    unsigned long flags)
{
    return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static void jendral_close_all(void)
{
    unsigned int i;
    for (i = 0; i < JENDRAL_HPC_EVENT_COUNT; ++i) {
        if (jendral_fds[i] >= 0) {
            close(jendral_fds[i]);
            jendral_fds[i] = -1;
        }
        jendral_ids[i] = 0;
    }
    jendral_hpc_ready = 0;
}

int PQCLEAN_DILITHIUM2_CLEAN_jendral_hpc_init(void)
{
    struct perf_event_attr attr;
    int leader = -1;
    unsigned int i;

    jendral_close_all();
    memset(&jendral_snapshot, 0, sizeof(jendral_snapshot));

    for (i = 0; i < JENDRAL_HPC_EVENT_COUNT; ++i) {
        memset(&attr, 0, sizeof(attr));
        attr.size = sizeof(attr);
        attr.type = jendral_events[i].type;
        attr.config = jendral_events[i].config;
        attr.disabled = 1;
        attr.exclude_kernel = 1;
        attr.exclude_hv = 1;
        attr.inherit = 0;
        attr.pinned = i == 0u ? 1u : 0u;
        attr.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_ID |
                           PERF_FORMAT_TOTAL_TIME_ENABLED |
                           PERF_FORMAT_TOTAL_TIME_RUNNING;

        jendral_fds[i] = (int)jendral_perf_event_open(
            &attr, 0, -1, leader, PERF_FLAG_FD_CLOEXEC);
        if (jendral_fds[i] < 0) {
            int saved = errno;
            jendral_close_all();
            jendral_snapshot.error_code = -saved;
            return -saved;
        }
        if (i == 0u) {
            leader = jendral_fds[i];
        }
        if (ioctl(jendral_fds[i], PERF_EVENT_IOC_ID, &jendral_ids[i]) != 0) {
            int saved = errno;
            jendral_close_all();
            jendral_snapshot.error_code = -saved;
            return -saved;
        }
    }

    jendral_hpc_ready = 1;
    return 0;
}

void PQCLEAN_DILITHIUM2_CLEAN_jendral_hpc_close(void)
{
    jendral_close_all();
}

void PQCLEAN_DILITHIUM2_CLEAN_jendral_set_measurement_enabled(int enabled)
{
    jendral_measurement_enabled = enabled != 0;
}

void PQCLEAN_DILITHIUM2_CLEAN_jendral_get_hpc_snapshot(jendral_hpc_snapshot *out)
{
    if (out != NULL) {
        *out = jendral_snapshot;
        out->target_invocations = jendral_target_invocations;
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_jendral_get_audit_snapshot(jendral_audit_snapshot *out)
{
    if (out != NULL) {
        *out = jendral_audit;
    }
}

const char *PQCLEAN_DILITHIUM2_CLEAN_jendral_event_name(unsigned int index)
{
    if (index >= JENDRAL_HPC_EVENT_COUNT) {
        return "unknown";
    }
    return jendral_events[index].name;
}

void PQCLEAN_DILITHIUM2_CLEAN_jendral_set_public_randomness(
    const uint8_t rnd[SEEDBYTES])
{
    memcpy(jendral_public_rnd, rnd, SEEDBYTES);
    jendral_public_rnd_configured = 1;
}

void PQCLEAN_DILITHIUM2_CLEAN_jendral_clear_public_randomness(void)
{
    memset(jendral_public_rnd, 0, sizeof(jendral_public_rnd));
    jendral_public_rnd_configured = 0;
}

static uint64_t jendral_tag(const uint8_t *data, size_t len)
{
    uint64_t h = UINT64_C(1469598103934665603);
    size_t i;
    for (i = 0; i < len; ++i) {
        h ^= data[i];
        h *= UINT64_C(1099511628211);
    }
    return h;
}

static inline void jendral_barrier(void)
{
    __asm__ volatile("" ::: "memory");
}

typedef struct {
    uint64_t value;
    uint64_t id;
} jendral_read_value;

typedef struct {
    uint64_t nr;
    uint64_t time_enabled;
    uint64_t time_running;
    jendral_read_value values[JENDRAL_HPC_EVENT_COUNT];
} jendral_group_read;

static void jendral_hpc_begin(void)
{
    jendral_snapshot.error_code = 0;
    jendral_barrier();
    if (ioctl(jendral_fds[0], PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP) != 0) {
        jendral_snapshot.error_code = -errno;
    }
    if (ioctl(jendral_fds[0], PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP) != 0) {
        jendral_snapshot.error_code = -errno;
    }
    jendral_barrier();
}

static void jendral_hpc_end(void)
{
    jendral_group_read data;
    ssize_t got;
    unsigned int i;
    unsigned int j;

    jendral_barrier();
    if (ioctl(jendral_fds[0], PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP) != 0) {
        jendral_snapshot.error_code = -errno;
    }
    jendral_barrier();

    memset(&data, 0, sizeof(data));
    got = read(jendral_fds[0], &data, sizeof(data));

    jendral_snapshot.sequence++;
    jendral_snapshot.target_invocations = jendral_target_invocations;
    jendral_snapshot.attack_build = JENDRAL_ATTACK_BUILD;
    jendral_snapshot.valid_mask = 0;
    memset(jendral_snapshot.values, 0, sizeof(jendral_snapshot.values));

    if (got < (ssize_t)(3u * sizeof(uint64_t))) {
        jendral_snapshot.error_code = got < 0 ? -errno : -EIO;
        return;
    }

    jendral_snapshot.time_enabled = data.time_enabled;
    jendral_snapshot.time_running = data.time_running;
    if (data.nr > JENDRAL_HPC_EVENT_COUNT) {
        data.nr = JENDRAL_HPC_EVENT_COUNT;
    }

    for (i = 0; i < data.nr; ++i) {
        for (j = 0; j < JENDRAL_HPC_EVENT_COUNT; ++j) {
            if (data.values[i].id == jendral_ids[j]) {
                jendral_snapshot.values[j] = data.values[i].value;
                jendral_snapshot.valid_mask |= (uint32_t)(1u << j);
                break;
            }
        }
    }
}

/*
 * Exact paper fault model used by this experiment:
 *
 *   normal: SHAKE256 absorbs key || rnd || mu
 *   fault:  the key absorb call is skipped; rnd || mu are still absorbed
 *
 * There is no runtime attack-mode branch in this victim operation. Baseline
 * and attack are separate compile-time binaries.
 */
JENDRAL_NOINLINE
void PQCLEAN_DILITHIUM2_CLEAN_jendral_target_key_absorb(
    shake256incctx *state,
    const uint8_t key[SEEDBYTES])
{
#if JENDRAL_ATTACK_BUILD == 0
    shake256_inc_absorb(state, key, SEEDBYTES);
#else
    __asm__ volatile("" : "+m"(*state) : "r"(key) : "memory");
#endif
}

static void jendral_hash_full(
    uint8_t out[CRHBYTES],
    const uint8_t key[SEEDBYTES],
    const uint8_t rnd[SEEDBYTES],
    const uint8_t mu[CRHBYTES])
{
    shake256incctx state;
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, key, SEEDBYTES);
    shake256_inc_absorb(&state, rnd, SEEDBYTES);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(out, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);
}

static void jendral_hash_public(
    uint8_t out[CRHBYTES],
    const uint8_t rnd[SEEDBYTES],
    const uint8_t mu[CRHBYTES])
{
    shake256incctx state;
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, rnd, SEEDBYTES);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(out, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);
}

int PQCLEAN_DILITHIUM2_CLEAN_jendral_derive_rhoprime(
    uint8_t rhoprime[CRHBYTES],
    const uint8_t key[SEEDBYTES],
    const uint8_t mu[CRHBYTES])
{
    uint8_t rnd[SEEDBYTES];
    uint8_t expected[CRHBYTES];
    uint8_t public_seed[CRHBYTES];
    shake256incctx state;

    memset(&jendral_audit, 0, sizeof(jendral_audit));
    jendral_audit.fault_requested = JENDRAL_ATTACK_BUILD;

    if (jendral_public_rnd_configured) {
        memcpy(rnd, jendral_public_rnd, SEEDBYTES);
        jendral_audit.rnd_is_public = 1;
    } else {
        if (randombytes(rnd, SEEDBYTES) != 0) {
            return -1;
        }
        jendral_audit.rnd_is_public = 0;
    }

    shake256_inc_init(&state);
    jendral_target_invocations++;

    if (jendral_measurement_enabled && jendral_hpc_ready) {
        jendral_hpc_begin();
        PQCLEAN_DILITHIUM2_CLEAN_jendral_target_key_absorb(&state, key);
        jendral_hpc_end();
    } else {
        PQCLEAN_DILITHIUM2_CLEAN_jendral_target_key_absorb(&state, key);
    }

    /* These steps remain unchanged in baseline and attack. */
    shake256_inc_absorb(&state, rnd, SEEDBYTES);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(rhoprime, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    memcpy(jendral_used_rhoprime, rhoprime, CRHBYTES);

    /* Audit computations are deliberately outside the PMU target window. */
    jendral_hash_full(expected, key, rnd, mu);
    jendral_hash_public(public_seed, rnd, mu);

    jendral_audit.rnd_tag = jendral_tag(rnd, SEEDBYTES);
    jendral_audit.mu_tag = jendral_tag(mu, CRHBYTES);
    jendral_audit.expected_seed_tag = jendral_tag(expected, CRHBYTES);
    jendral_audit.used_seed_tag = jendral_tag(rhoprime, CRHBYTES);
    jendral_audit.public_seed_tag = jendral_tag(public_seed, CRHBYTES);
    jendral_audit.key_absorb_executed = JENDRAL_ATTACK_BUILD == 0;
    jendral_audit.key_absorb_skipped = JENDRAL_ATTACK_BUILD != 0;
    jendral_audit.seed_matches_expected =
        memcmp(rhoprime, expected, CRHBYTES) == 0;
    jendral_audit.seed_matches_public =
        memcmp(rhoprime, public_seed, CRHBYTES) == 0;

#if JENDRAL_ATTACK_BUILD == 0
    jendral_audit.fault_applied = 0;
    jendral_audit.semantic_valid =
        jendral_audit.key_absorb_executed &&
        jendral_audit.seed_matches_expected &&
        !jendral_audit.seed_matches_public;
#else
    jendral_audit.fault_applied =
        jendral_audit.key_absorb_skipped &&
        jendral_audit.seed_matches_public &&
        !jendral_audit.seed_matches_expected;
    jendral_audit.semantic_valid = jendral_audit.fault_applied;
#endif

    return 0;
}

void PQCLEAN_DILITHIUM2_CLEAN_jendral_record_nonce(uint16_t nonce)
{
    jendral_final_nonce = nonce;
    jendral_audit.final_nonce = nonce;
}

int PQCLEAN_DILITHIUM2_CLEAN_jendral_check_single_trace_relation(
    const uint8_t *sig,
    const uint8_t *sk)
{
    uint8_t rho[SEEDBYTES];
    uint8_t tr[SEEDBYTES];
    uint8_t key[SEEDBYTES];
    uint8_t cseed[SEEDBYTES];
    polyveck t0;
    polyveck s2;
    polyveck h;
    polyvecl s1;
    polyvecl y;
    polyvecl z;
    polyvecl cs1;
    polyvecl expected_z;
    poly cp;
    unsigned int i;
    unsigned int j;
    unsigned int mismatches = 0;

    PQCLEAN_DILITHIUM2_CLEAN_unpack_sk(
        rho, tr, key, &t0, &s1, &s2, sk);
    if (PQCLEAN_DILITHIUM2_CLEAN_unpack_sig(cseed, &z, &h, sig) != 0) {
        jendral_audit.relation_mismatches = (uint32_t)(L * N);
        jendral_audit.relation_valid = 0;
        jendral_audit.semantic_valid = 0;
        return -1;
    }

    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_uniform_gamma1(
        &y, jendral_used_rhoprime, jendral_final_nonce);
    PQCLEAN_DILITHIUM2_CLEAN_poly_challenge(&cp, cseed);
    PQCLEAN_DILITHIUM2_CLEAN_poly_ntt(&cp);
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_ntt(&s1);
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_pointwise_poly_montgomery(
        &cs1, &cp, &s1);
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_invntt_tomont(&cs1);
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_add(&expected_z, &cs1, &y);
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_reduce(&expected_z);

    for (i = 0; i < (unsigned int)L; ++i) {
        for (j = 0; j < (unsigned int)N; ++j) {
            if (expected_z.vec[i].coeffs[j] != z.vec[i].coeffs[j]) {
                mismatches++;
            }
        }
    }

    jendral_audit.relation_mismatches = mismatches;
    jendral_audit.relation_valid = mismatches == 0u;
    jendral_audit.semantic_valid =
        jendral_audit.semantic_valid && jendral_audit.relation_valid;
    return mismatches == 0u ? 0 : -1;
}
