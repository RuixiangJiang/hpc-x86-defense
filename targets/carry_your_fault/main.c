#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "carry_your_fault_a2b.h"
#include "carry_your_fault_microarch_events_generated.h"

#include <errno.h>
#include <inttypes.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef CYF_BUILD_MODE
#define CYF_BUILD_MODE 0
#endif

#ifndef CYF_COUNTER_SET
#define CYF_COUNTER_SET 0
#endif

#ifndef CYF_WINDOW_MODE
#define CYF_WINDOW_MODE 0
#endif

#ifndef CYF_PMU_TYPE
#define CYF_PMU_TYPE 4u
#endif

#ifndef CYF_LOAD_CONFIG
#define CYF_LOAD_CONFIG UINT64_C(0x81d0)
#endif

#ifndef CYF_STORE_CONFIG
#define CYF_STORE_CONFIG UINT64_C(0x82d0)
#endif

#define CYF_MODE_BASELINE 0
#define CYF_MODE_STUCK_AT_1 1

#define CYF_WINDOW_EXACT_A2B 0
#define CYF_WINDOW_POST_FAULT 1

#define CYF_COUNTER_SET_STRUCTURAL 0
#define CYF_COUNTER_SET_CACHE 1
#define CYF_COUNTER_SET_CACHE_DETAIL 2
#define CYF_COUNTER_SET_LOAD_HITS 3
#define CYF_COUNTER_SET_LOAD_MISSES_LATENCY 4
#define CYF_COUNTER_SET_STALLS 5
#define CYF_COUNTER_SET_RECOVERY 6

#if CYF_BUILD_MODE != CYF_MODE_BASELINE && \
    CYF_BUILD_MODE != CYF_MODE_STUCK_AT_1
#error "invalid CYF_BUILD_MODE"
#endif

#if CYF_COUNTER_SET < CYF_COUNTER_SET_STRUCTURAL || \
    CYF_COUNTER_SET > CYF_COUNTER_SET_RECOVERY
#error "invalid CYF_COUNTER_SET"
#endif

#if CYF_WINDOW_MODE != CYF_WINDOW_EXACT_A2B && \
    CYF_WINDOW_MODE != CYF_WINDOW_POST_FAULT
#error "invalid CYF_WINDOW_MODE"
#endif

enum {
    CYF_EVENT_COUNT = 6
};

typedef struct {
    const char *name;
    uint32_t type;
    uint64_t config;
    uint64_t config1;
    uint64_t config2;
    uint32_t precise_ip;
    uint32_t available;
} event_desc;

#define EVENT_GENERIC(name_, config_) \
    {name_, PERF_TYPE_HARDWARE, config_, UINT64_C(0), UINT64_C(0), 0u, 1u}

#define EVENT_RAW(name_, macro_) \
    { \
        name_, \
        CYF_EVT_##macro_##_TYPE, \
        CYF_EVT_##macro_##_CONFIG, \
        CYF_EVT_##macro_##_CONFIG1, \
        CYF_EVT_##macro_##_CONFIG2, \
        CYF_EVT_##macro_##_PRECISE_IP, \
        CYF_EVT_##macro_##_AVAILABLE \
    }

#define CACHE_CONFIG(cache_, op_, result_) \
    ((uint64_t)(cache_) | \
     ((uint64_t)(op_) << 8) | \
     ((uint64_t)(result_) << 16))

#if CYF_COUNTER_SET == CYF_COUNTER_SET_STRUCTURAL
static const event_desc EVENTS[CYF_EVENT_COUNT] = {
    EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    EVENT_GENERIC("instructions", PERF_COUNT_HW_INSTRUCTIONS),
    EVENT_GENERIC("branches", PERF_COUNT_HW_BRANCH_INSTRUCTIONS),
    EVENT_GENERIC("branch_misses", PERF_COUNT_HW_BRANCH_MISSES),
    {
        "retired_loads", CYF_PMU_TYPE, CYF_LOAD_CONFIG,
        UINT64_C(0), UINT64_C(0), 0u, 1u
    },
    {
        "retired_stores", CYF_PMU_TYPE, CYF_STORE_CONFIG,
        UINT64_C(0), UINT64_C(0), 0u, 1u
    },
};
#elif CYF_COUNTER_SET == CYF_COUNTER_SET_CACHE
static const event_desc EVENTS[CYF_EVENT_COUNT] = {
    EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    EVENT_GENERIC("instructions", PERF_COUNT_HW_INSTRUCTIONS),
    {
        "l1d_read_misses", PERF_TYPE_HW_CACHE,
        CACHE_CONFIG(
            PERF_COUNT_HW_CACHE_L1D,
            PERF_COUNT_HW_CACHE_OP_READ,
            PERF_COUNT_HW_CACHE_RESULT_MISS),
        UINT64_C(0), UINT64_C(0), 0u, 1u
    },
    {
        "l1i_read_misses", PERF_TYPE_HW_CACHE,
        CACHE_CONFIG(
            PERF_COUNT_HW_CACHE_L1I,
            PERF_COUNT_HW_CACHE_OP_READ,
            PERF_COUNT_HW_CACHE_RESULT_MISS),
        UINT64_C(0), UINT64_C(0), 0u, 1u
    },
    {
        "llc_read_misses", PERF_TYPE_HW_CACHE,
        CACHE_CONFIG(
            PERF_COUNT_HW_CACHE_LL,
            PERF_COUNT_HW_CACHE_OP_READ,
            PERF_COUNT_HW_CACHE_RESULT_MISS),
        UINT64_C(0), UINT64_C(0), 0u, 1u
    },
    {
        "dtlb_read_misses", PERF_TYPE_HW_CACHE,
        CACHE_CONFIG(
            PERF_COUNT_HW_CACHE_DTLB,
            PERF_COUNT_HW_CACHE_OP_READ,
            PERF_COUNT_HW_CACHE_RESULT_MISS),
        UINT64_C(0), UINT64_C(0), 0u, 1u
    },
};
#elif CYF_COUNTER_SET == CYF_COUNTER_SET_CACHE_DETAIL
static const event_desc EVENTS[CYF_EVENT_COUNT] = {
    EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    EVENT_GENERIC("instructions", PERF_COUNT_HW_INSTRUCTIONS),
    EVENT_GENERIC("cache_references", PERF_COUNT_HW_CACHE_REFERENCES),
    EVENT_GENERIC("cache_misses", PERF_COUNT_HW_CACHE_MISSES),
    EVENT_RAW("l1d_replacements", L1D_REPLACEMENTS),
    EVENT_RAW("l2_request_misses", L2_REQUEST_MISSES),
};
#elif CYF_COUNTER_SET == CYF_COUNTER_SET_LOAD_HITS
static const event_desc EVENTS[CYF_EVENT_COUNT] = {
    EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    EVENT_GENERIC("instructions", PERF_COUNT_HW_INSTRUCTIONS),
    EVENT_RAW("load_l1_hit", LOAD_L1_HIT),
    EVENT_RAW("load_l2_hit", LOAD_L2_HIT),
    EVENT_RAW("load_l3_hit", LOAD_L3_HIT),
    EVENT_RAW("load_l3_miss", LOAD_L3_MISS),
};
#elif CYF_COUNTER_SET == CYF_COUNTER_SET_LOAD_MISSES_LATENCY
static const event_desc EVENTS[CYF_EVENT_COUNT] = {
    EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    EVENT_GENERIC("instructions", PERF_COUNT_HW_INSTRUCTIONS),
    EVENT_RAW("load_l1_miss", LOAD_L1_MISS),
    EVENT_RAW("load_l2_miss", LOAD_L2_MISS),
    EVENT_RAW("load_l3_miss", LOAD_L3_MISS),
    EVENT_RAW("long_latency_loads", LONG_LATENCY_LOADS),
};
#elif CYF_COUNTER_SET == CYF_COUNTER_SET_STALLS
static const event_desc EVENTS[CYF_EVENT_COUNT] = {
    EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    EVENT_GENERIC("instructions", PERF_COUNT_HW_INSTRUCTIONS),
    EVENT_GENERIC(
        "stalled_frontend_cycles",
        PERF_COUNT_HW_STALLED_CYCLES_FRONTEND),
    EVENT_GENERIC(
        "stalled_backend_cycles",
        PERF_COUNT_HW_STALLED_CYCLES_BACKEND),
    EVENT_RAW("stalls_l1d_miss", STALLS_L1D_MISS),
    EVENT_RAW("stalls_mem_any", STALLS_MEM_ANY),
};
#else
static const event_desc EVENTS[CYF_EVENT_COUNT] = {
    EVENT_GENERIC("cycles", PERF_COUNT_HW_CPU_CYCLES),
    EVENT_GENERIC("instructions", PERF_COUNT_HW_INSTRUCTIONS),
    EVENT_RAW("machine_clears", MACHINE_CLEARS),
    EVENT_RAW("memory_ordering_clears", MEMORY_ORDERING_CLEARS),
    EVENT_RAW("recovery_cycles", RECOVERY_CYCLES),
    EVENT_RAW("recovery_cycles_any", RECOVERY_CYCLES_ANY),
};
#endif

typedef struct {
    int leader_fd;
    int fds[CYF_EVENT_COUNT];
    uint64_t ids[CYF_EVENT_COUNT];
    uint32_t requested_mask;
    uint32_t available_mask;
    uint32_t open_error_mask;
    unsigned int opened;
} perf_group;

typedef struct {
    uint64_t nr;
    uint64_t time_enabled;
    uint64_t time_running;
    struct {
        uint64_t value;
        uint64_t id;
    } values[CYF_EVENT_COUNT];
} perf_group_read;

typedef struct {
    uint64_t time_enabled;
    uint64_t time_running;
    uint64_t counters[CYF_EVENT_COUNT];
    uint32_t requested_mask;
    uint32_t available_mask;
    uint32_t open_error_mask;
    uint32_t valid_mask;
    int32_t error_code;
} perf_snapshot;

static volatile uint16_t g_sink;

static long perf_event_open(
    struct perf_event_attr *attr,
    pid_t pid,
    int cpu,
    int group_fd,
    unsigned long flags)
{
    return syscall(
        __NR_perf_event_open,
        attr,
        pid,
        cpu,
        group_fd,
        flags);
}

static unsigned long parse_ulong(const char *text, const char *name)
{
    char *end = NULL;
    unsigned long value;

    errno = 0;
    value = strtoul(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0') {
        fprintf(stderr, "[error] invalid %s: %s\n", name, text);
        exit(EXIT_FAILURE);
    }
    return value;
}

static uint64_t mix64(uint64_t value)
{
    value ^= value >> 30;
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27;
    value *= UINT64_C(0x94d049bb133111eb);
    value ^= value >> 31;
    return value;
}

static uint64_t sample_random(
    uint32_t domain,
    uint64_t sample,
    uint32_t attempt)
{
    uint64_t seed =
        ((uint64_t)domain << 32) ^
        sample ^
        ((uint64_t)attempt * UINT64_C(0x9e3779b97f4a7c15));
    return mix64(seed);
}

static int pin_to_cpu(unsigned int cpu)
{
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        return -errno;
    }
    return 0;
}

static void close_perf_group(perf_group *group)
{
    unsigned int i;

    for (i = 0; i < CYF_EVENT_COUNT; ++i) {
        if (group->fds[i] >= 0) {
            close(group->fds[i]);
            group->fds[i] = -1;
        }
        group->ids[i] = 0;
    }
    group->leader_fd = -1;
    group->opened = 0;
}

static int init_perf_group(perf_group *group)
{
    struct perf_event_attr attr;
    unsigned int i;

    memset(group, 0, sizeof(*group));
    group->leader_fd = -1;
    for (i = 0; i < CYF_EVENT_COUNT; ++i) {
        group->fds[i] = -1;
        group->requested_mask |= UINT32_C(1) << i;
    }

    for (i = 0; i < CYF_EVENT_COUNT; ++i) {
        int saved;
        int fd;

        if (!EVENTS[i].available) {
            group->open_error_mask |= UINT32_C(1) << i;
            continue;
        }

        memset(&attr, 0, sizeof(attr));
        attr.size = sizeof(attr);
        attr.type = EVENTS[i].type;
        attr.config = EVENTS[i].config;
        attr.config1 = EVENTS[i].config1;
        attr.config2 = EVENTS[i].config2;
        attr.precise_ip = EVENTS[i].precise_ip;
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

        fd = (int)perf_event_open(
            &attr,
            0,
            -1,
            group->leader_fd,
            PERF_FLAG_FD_CLOEXEC);
        if (fd < 0) {
            saved = errno;
            if (i < 2u) {
                close_perf_group(group);
                return -saved;
            }
            group->open_error_mask |= UINT32_C(1) << i;
            continue;
        }

        group->fds[i] = fd;
        if (i == 0u) {
            group->leader_fd = fd;
        }

        if (ioctl(fd, PERF_EVENT_IOC_ID, &group->ids[i]) != 0) {
            saved = errno;
            close(fd);
            group->fds[i] = -1;
            if (i < 2u) {
                close_perf_group(group);
                return -saved;
            }
            group->open_error_mask |= UINT32_C(1) << i;
            continue;
        }

        group->available_mask |= UINT32_C(1) << i;
        group->opened++;
    }

    if ((group->available_mask & UINT32_C(0x3)) != UINT32_C(0x3)) {
        close_perf_group(group);
        return -ENODEV;
    }
    return 0;
}

static int map_group_read(
    const perf_group *group,
    const perf_group_read *raw,
    perf_snapshot *snapshot)
{
    uint64_t i;
    unsigned int j;

    snapshot->time_enabled = raw->time_enabled;
    snapshot->time_running = raw->time_running;
    snapshot->requested_mask = group->requested_mask;
    snapshot->available_mask = group->available_mask;
    snapshot->open_error_mask = group->open_error_mask;

    if (raw->nr > CYF_EVENT_COUNT) {
        snapshot->error_code = -EIO;
        return -EIO;
    }

    for (i = 0; i < raw->nr; ++i) {
        int found = 0;
        for (j = 0; j < CYF_EVENT_COUNT; ++j) {
            if (group->fds[j] >= 0 &&
                raw->values[i].id == group->ids[j]) {
                snapshot->counters[j] = raw->values[i].value;
                snapshot->valid_mask |= UINT32_C(1) << j;
                found = 1;
                break;
            }
        }
        if (!found) {
            snapshot->error_code = -EINVAL;
            return -EINVAL;
        }
    }

    if ((snapshot->valid_mask & group->available_mask) !=
        group->available_mask) {
        snapshot->error_code = -EIO;
        return -EIO;
    }

    snapshot->error_code = 0;
    return 0;
}


typedef struct {
    uint32_t w_prefix_share0;
    uint32_t w_prefix_share1;
    uint32_t x_prefix_share0;
    uint32_t x_prefix_share1;
    uint32_t x_bit_share0;
    uint32_t x_bit_share1;
    uint32_t r_share0;
    uint32_t r_share1;
    uint32_t secand_mask0;
    uint32_t secand_mask1;
} post_context;

static const char *window_name(void)
{
#if CYF_WINDOW_MODE == CYF_WINDOW_EXACT_A2B
    return "exact-a2b";
#else
    return "post-fault";
#endif
}

static int finish_measurement(
    perf_group *group,
    perf_snapshot *snapshot)
{
    perf_group_read raw;
    ssize_t got;

    if (ioctl(
            group->leader_fd,
            PERF_EVENT_IOC_DISABLE,
            PERF_IOC_FLAG_GROUP) != 0) {
        return -errno;
    }

    memset(&raw, 0, sizeof(raw));
    got = read(group->leader_fd, &raw, sizeof(raw));
    if (got < 0) {
        return -errno;
    }
    if ((size_t)got < 3u * sizeof(uint64_t)) {
        return -EIO;
    }

    return map_group_read(group, &raw, snapshot);
}

static int prepare_measurement(
    perf_group *group,
    perf_snapshot *snapshot)
{
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->requested_mask = group->requested_mask;
    snapshot->available_mask = group->available_mask;
    snapshot->open_error_mask = group->open_error_mask;

    if (ioctl(
            group->leader_fd,
            PERF_EVENT_IOC_RESET,
            PERF_IOC_FLAG_GROUP) != 0) {
        return -errno;
    }
    return 0;
}

__attribute__((noinline, noclone, noipa, used, aligned(4096)))
static int measure_exact_target(
    perf_group *group,
    uint16_t target_share,
    uint16_t second_share,
    uint16_t *boolean_share,
    perf_snapshot *snapshot)
{
    int rc = prepare_measurement(group, snapshot);
    if (rc != 0) {
        return rc;
    }

    __asm__ __volatile__(
        ""
        :
        : "r"(target_share), "r"(second_share)
        : "memory");

    if (ioctl(
            group->leader_fd,
            PERF_EVENT_IOC_ENABLE,
            PERF_IOC_FLAG_GROUP) != 0) {
        return -errno;
    }

    __asm__ __volatile__("" ::: "memory");
    *boolean_share = cyf_a2b_target(target_share, second_share);
    g_sink = *boolean_share;
    __asm__ __volatile__("" ::: "memory");

    return finish_measurement(group, snapshot);
}

__attribute__((noinline, noclone, noipa, used, aligned(4096)))
static int measure_post_target(
    perf_group *group,
    uint16_t boolean_share,
    uint16_t second_share,
    const post_context *context,
    cyf_post_result *post,
    perf_snapshot *snapshot)
{
    int rc = prepare_measurement(group, snapshot);
    if (rc != 0) {
        return rc;
    }

    __asm__ __volatile__(
        ""
        :
        : "r"(boolean_share), "r"(second_share), "r"(context)
        : "memory");

    if (ioctl(
            group->leader_fd,
            PERF_EVENT_IOC_ENABLE,
            PERF_IOC_FLAG_GROUP) != 0) {
        return -errno;
    }

    __asm__ __volatile__("" ::: "memory");
    cyf_post_fault_target(
        boolean_share,
        second_share,
        context->w_prefix_share0,
        context->w_prefix_share1,
        context->x_prefix_share0,
        context->x_prefix_share1,
        context->x_bit_share0,
        context->x_bit_share1,
        context->r_share0,
        context->r_share1,
        context->secand_mask0,
        context->secand_mask1,
        post);
    g_sink = (uint16_t)post->unmasked_compare;
    __asm__ __volatile__("" ::: "memory");

    return finish_measurement(group, snapshot);
}

static void build_propagating_case(
    uint32_t domain,
    uint64_t sample,
    uint32_t attempt,
    uint16_t *unmasked,
    uint16_t *original_share,
    uint16_t *second_share)
{
    uint64_t random = sample_random(domain, sample, attempt);
    uint16_t share;

    /*
     * Bits 11..15 are all one.  Establishing bit 11 in the arithmetic
     * share therefore adds 2^11 to the recombined value and propagates a
     * carry through bit 15, wrapping those bits to zero.
     */
    *unmasked = (uint16_t)(
        UINT16_C(0xf800) |
        (uint16_t)(random & UINT16_C(0x07ff)));

    share = (uint16_t)(random >> 16);
    share &= (uint16_t)~CYF_TARGET_MASK;

    *original_share = share;
    *second_share = (uint16_t)(*unmasked - share);
}

static void build_post_context(
    uint32_t domain,
    uint64_t sample,
    post_context *context)
{
    uint64_t a = sample_random(
        domain ^ UINT32_C(0x504f5354), sample, 1u);
    uint64_t b = mix64(a ^ UINT64_C(0x9e3779b97f4a7c15));
    uint64_t c = mix64(b ^ UINT64_C(0xd1b54a32d192ed03));
    uint64_t d = mix64(c ^ UINT64_C(0x94d049bb133111eb));
    uint32_t x_bit0;

    context->w_prefix_share0 =
        (uint32_t)a & CYF_POST_PREFIX_MASK;
    context->w_prefix_share1 =
        context->w_prefix_share0 ^ CYF_POST_PREFIX_MASK;

    context->x_prefix_share0 =
        (uint32_t)(a >> 32) & CYF_POST_PREFIX_MASK;
    context->x_prefix_share1 =
        context->x_prefix_share0 ^ CYF_POST_PREFIX_MASK;

    x_bit0 = (uint32_t)(b & 1u);
    context->x_bit_share0 = x_bit0;
    context->x_bit_share1 = x_bit0 ^ 1u;

    context->r_share0 = (uint32_t)(b >> 32);
    context->r_share1 =
        context->r_share0 ^ UINT32_C(0xffffffff);
    context->secand_mask0 = (uint32_t)c;
    context->secand_mask1 = (uint32_t)d;
}

static int semantic_check(
    uint16_t unmasked,
    uint16_t original_share,
    uint16_t target_share,
    uint16_t second_share,
    uint16_t boolean_share,
    const cyf_post_result *post,
    int attack_mode,
    int *fault_applied,
    int *stuck_at_one,
    int *a2b_relation,
    int *propagated_to_msb,
    int *propagated_to_compare_bit,
    int *predicted_decryption_failure,
    uint16_t *observed_unmasked,
    unsigned int *decoded_before,
    unsigned int *decoded_after,
    unsigned int *compare_before,
    unsigned int *compare_after)
{
    uint16_t expected_after =
        cyf_recombine_arithmetic(target_share, second_share);
    uint32_t expected_w;
    uint32_t expected_failure;

    *observed_unmasked = (uint16_t)(boolean_share ^ second_share);
    *decoded_before = (unsigned int)((unmasked >> 15) & 1u);
    *decoded_after =
        (unsigned int)((*observed_unmasked >> 15) & 1u);
    *compare_before =
        (unsigned int)((unmasked >> CYF_TARGET_BIT) & 1u);
    *compare_after =
        (unsigned int)((*observed_unmasked >> CYF_TARGET_BIT) & 1u);

    *fault_applied =
        attack_mode &&
        (original_share & CYF_TARGET_MASK) == 0u &&
        (target_share & CYF_TARGET_MASK) != 0u;

    *stuck_at_one =
        !attack_mode
            ? target_share == original_share
            : target_share ==
                  (uint16_t)(original_share | CYF_TARGET_MASK);

    *a2b_relation = *observed_unmasked == expected_after;
    *propagated_to_msb =
        attack_mode &&
        *decoded_before == 1u &&
        *decoded_after == 0u;
    *propagated_to_compare_bit =
        attack_mode &&
        *compare_before == 1u &&
        *compare_after == 0u;

    expected_w =
        attack_mode ? UINT32_C(0xfffffffe) : UINT32_C(0xffffffff);
    expected_failure = attack_mode ? 1u : 0u;
    *predicted_decryption_failure =
        *propagated_to_compare_bit &&
        post->comparison_failure == expected_failure;

    if (!*stuck_at_one || !*a2b_relation) {
        return 0;
    }

    if (post->unmasked_w != expected_w ||
        post->unmasked_x != UINT32_C(0xffffffff) ||
        post->unmasked_compare != expected_w ||
        post->comparison_failure != expected_failure) {
        return 0;
    }

    if (!attack_mode) {
        return *observed_unmasked == unmasked &&
               *decoded_before == 1u &&
               *decoded_after == 1u &&
               *compare_before == 1u &&
               *compare_after == 1u;
    }

    return *fault_applied &&
           *propagated_to_msb &&
           *propagated_to_compare_bit &&
           *predicted_decryption_failure &&
           *observed_unmasked ==
               (uint16_t)(unmasked + CYF_TARGET_MASK);
}

static int run_self_test(void)
{
    unsigned int mode;
    uint64_t sample;

    cyf_a2b_init(UINT32_C(0x43594631));

    for (mode = 0; mode <= 1; ++mode) {
        for (sample = 0; sample < 10000; ++sample) {
            uint16_t unmasked;
            uint16_t original_share;
            uint16_t second_share;
            uint16_t target_share;
            uint16_t boolean_share;
            uint16_t observed;
            unsigned int decoded_before;
            unsigned int decoded_after;
            unsigned int compare_before;
            unsigned int compare_after;
            int fault_applied;
            int stuck_at_one;
            int relation;
            int propagated;
            int compare_propagated;
            int predicted_failure;
            int ok;
            post_context context;
            cyf_post_result post;

            build_propagating_case(
                UINT32_C(0x53544654) + mode,
                sample,
                1u,
                &unmasked,
                &original_share,
                &second_share);
            build_post_context(
                UINT32_C(0x53544654) + mode,
                sample,
                &context);

            target_share = mode == CYF_MODE_STUCK_AT_1
                ? (uint16_t)(original_share | CYF_TARGET_MASK)
                : original_share;

            boolean_share =
                cyf_a2b_target(target_share, second_share);
            memset(&post, 0, sizeof(post));
            cyf_post_fault_target(
                boolean_share,
                second_share,
                context.w_prefix_share0,
                context.w_prefix_share1,
                context.x_prefix_share0,
                context.x_prefix_share1,
                context.x_bit_share0,
                context.x_bit_share1,
                context.r_share0,
                context.r_share1,
                context.secand_mask0,
                context.secand_mask1,
                &post);

            ok = semantic_check(
                unmasked,
                original_share,
                target_share,
                second_share,
                boolean_share,
                &post,
                mode == CYF_MODE_STUCK_AT_1,
                &fault_applied,
                &stuck_at_one,
                &relation,
                &propagated,
                &compare_propagated,
                &predicted_failure,
                &observed,
                &decoded_before,
                &decoded_after,
                &compare_before,
                &compare_after);

            if (!ok) {
                fprintf(
                    stderr,
                    "[error] self-test failed: mode=%u sample=%" PRIu64 "\n",
                    mode,
                    sample);
                return EXIT_FAILURE;
            }
        }
    }

    printf(
        "[ok] Carry Your Fault semantic self-test passed "
        "(window=%s)\n",
        window_name());
    return EXIT_SUCCESS;
}

static void write_csv_header(FILE *out)
{
    unsigned int i;

    fputs(
        "sample,mode,window,message_domain,attempt,"
        "collection_block,collection_round,collection_order,"
        "experiment_run,experiment_seed,pair_kind,pair_order,pair_position,"
        "target_coeff,target_bit,"
        "unmasked_before,original_share,target_share,second_share,"
        "boolean_share,observed_unmasked,"
        "original_share_bit,target_share_bit,"
        "decoded_before,decoded_after,"
        "comparison_bit_before,comparison_bit_after,"
        "post_unmasked_w,post_unmasked_x,post_unmasked_compare,"
        "post_comparison_failure,"
        "fault_requested,fault_applied,stuck_at_one,"
        "a2b_relation,propagated_to_msb,propagated_to_compare_bit,"
        "predicted_decryption_failure,oracle_success,semantic_valid,"
        "counter_set,time_enabled,time_running,running_percent,"
        "requested_mask,available_mask,open_error_mask,"
        "valid_mask,error_code",
        out);

    for (i = 0; i < CYF_EVENT_COUNT; ++i) {
        fprintf(out, ",%s", EVENTS[i].name);
    }
    fputc('\n', out);
}

int main(int argc, char **argv)
{
    const char *output_path = NULL;
    unsigned long samples = 500;
    unsigned long warmup = 100;
    unsigned long cpu = 0;
    unsigned long target_coeff = 17;
    unsigned long message_domain = UINT32_C(0x43594631);
    unsigned long sample_offset = 0;
    unsigned long collection_block = 0;
    unsigned long collection_round = 0;
    unsigned long collection_order = 0;
    unsigned long experiment_run = 0;
    unsigned long experiment_seed = 0;
    unsigned long pair_kind = 0;
    unsigned long pair_order = 0;
    unsigned long pair_position = 0;
    unsigned long i;
    int self_test = 0;
    int ret = EXIT_FAILURE;
    perf_group group;
    FILE *out = NULL;

    memset(&group, 0, sizeof(group));
    group.leader_fd = -1;

    for (i = 1; i < (unsigned long)argc; ++i) {
        if (strcmp(argv[i], "--output") == 0 &&
            i + 1 < (unsigned long)argc) {
            output_path = argv[++i];
        } else if (strcmp(argv[i], "--samples") == 0 &&
                   i + 1 < (unsigned long)argc) {
            samples = parse_ulong(argv[++i], "samples");
        } else if (strcmp(argv[i], "--warmup") == 0 &&
                   i + 1 < (unsigned long)argc) {
            warmup = parse_ulong(argv[++i], "warmup");
        } else if (strcmp(argv[i], "--cpu") == 0 &&
                   i + 1 < (unsigned long)argc) {
            cpu = parse_ulong(argv[++i], "cpu");
        } else if (strcmp(argv[i], "--target-coeff") == 0 &&
                   i + 1 < (unsigned long)argc) {
            target_coeff = parse_ulong(argv[++i], "target coefficient");
        } else if (strcmp(argv[i], "--message-domain") == 0 &&
                   i + 1 < (unsigned long)argc) {
            message_domain = parse_ulong(argv[++i], "message domain");
        } else if (strcmp(argv[i], "--sample-offset") == 0 &&
                   i + 1 < (unsigned long)argc) {
            sample_offset = parse_ulong(argv[++i], "sample offset");
        } else if (strcmp(argv[i], "--collection-block") == 0 &&
                   i + 1 < (unsigned long)argc) {
            collection_block = parse_ulong(argv[++i], "collection block");
        } else if (strcmp(argv[i], "--collection-round") == 0 &&
                   i + 1 < (unsigned long)argc) {
            collection_round = parse_ulong(argv[++i], "collection round");
        } else if (strcmp(argv[i], "--collection-order") == 0 &&
                   i + 1 < (unsigned long)argc) {
            collection_order = parse_ulong(argv[++i], "collection order");
        } else if (strcmp(argv[i], "--experiment-run") == 0 &&
                   i + 1 < (unsigned long)argc) {
            experiment_run = parse_ulong(argv[++i], "experiment run");
        } else if (strcmp(argv[i], "--experiment-seed") == 0 &&
                   i + 1 < (unsigned long)argc) {
            experiment_seed = parse_ulong(argv[++i], "experiment seed");
        } else if (strcmp(argv[i], "--pair-kind") == 0 &&
                   i + 1 < (unsigned long)argc) {
            pair_kind = parse_ulong(argv[++i], "pair kind");
        } else if (strcmp(argv[i], "--pair-order") == 0 &&
                   i + 1 < (unsigned long)argc) {
            pair_order = parse_ulong(argv[++i], "pair order");
        } else if (strcmp(argv[i], "--pair-position") == 0 &&
                   i + 1 < (unsigned long)argc) {
            pair_position = parse_ulong(argv[++i], "pair position");
        } else if (strcmp(argv[i], "--self-test") == 0) {
            self_test = 1;
        } else {
            fprintf(
                stderr,
                "usage: %s [--self-test] --output FILE "
                "[--samples N] [--warmup N] [--cpu N] "
                "[--target-coeff N] [--message-domain N] "
                "[--sample-offset N] [--collection-block N] "
                "[--collection-round N] [--collection-order N] "
                "[--experiment-run N] [--experiment-seed N] "
                "[--pair-kind N] [--pair-order N] "
                "[--pair-position N]\n",
                argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (self_test) {
        return run_self_test();
    }

    if (output_path == NULL || samples == 0u || target_coeff >= 256u) {
        fprintf(stderr, "[error] invalid output/sample configuration\n");
        return EXIT_FAILURE;
    }

    if (pin_to_cpu((unsigned int)cpu) != 0) {
        fprintf(stderr, "[error] unable to pin to CPU %lu\n", cpu);
        return EXIT_FAILURE;
    }

    cyf_a2b_init(UINT32_C(0x43594631));

    for (i = 0; i < warmup; ++i) {
        uint16_t unmasked;
        uint16_t original_share;
        uint16_t second_share;
        uint16_t target_share;
        uint16_t boolean_share;
        post_context context;
        cyf_post_result post;

        build_propagating_case(
            (uint32_t)message_domain ^ UINT32_C(0x5741524d),
            (uint64_t)sample_offset + (uint64_t)i,
            1u,
            &unmasked,
            &original_share,
            &second_share);
        build_post_context(
            (uint32_t)message_domain ^ UINT32_C(0x5741524d),
            (uint64_t)sample_offset + (uint64_t)i,
            &context);

#if CYF_BUILD_MODE == CYF_MODE_STUCK_AT_1
        target_share = (uint16_t)(original_share | CYF_TARGET_MASK);
#else
        target_share = original_share;
#endif
        boolean_share = cyf_a2b_target(target_share, second_share);
        cyf_post_fault_target(
            boolean_share,
            second_share,
            context.w_prefix_share0,
            context.w_prefix_share1,
            context.x_prefix_share0,
            context.x_prefix_share1,
            context.x_bit_share0,
            context.x_bit_share1,
            context.r_share0,
            context.r_share1,
            context.secand_mask0,
            context.secand_mask1,
            &post);
        g_sink = (uint16_t)post.unmasked_compare;
    }

    {
        int rc = init_perf_group(&group);
        if (rc != 0) {
            fprintf(
                stderr,
                "[error] perf_event_open group failed: %s (%d)\n",
                strerror(-rc),
                rc);
            return EXIT_FAILURE;
        }
    }

    out = fopen(output_path, "w");
    if (out == NULL) {
        perror("fopen output");
        close_perf_group(&group);
        return EXIT_FAILURE;
    }
    write_csv_header(out);

    for (i = 0; i < samples; ++i) {
        uint16_t unmasked;
        uint16_t original_share;
        uint16_t second_share;
        uint16_t target_share;
        uint16_t boolean_share = 0;
        uint16_t observed_unmasked = 0;
        unsigned int decoded_before = 0;
        unsigned int decoded_after = 0;
        unsigned int compare_before = 0;
        unsigned int compare_after = 0;
        int fault_requested = CYF_BUILD_MODE == CYF_MODE_STUCK_AT_1;
        int fault_applied = 0;
        int stuck_at_one = 0;
        int a2b_relation = 0;
        int propagated_to_msb = 0;
        int propagated_to_compare_bit = 0;
        int predicted_failure = 0;
        int oracle_success;
        int semantic_valid;
        int measure_rc;
        perf_snapshot snapshot;
        double running_percent;
        unsigned int event_index;
        uint64_t sample_id = (uint64_t)sample_offset + (uint64_t)i;
        post_context context;
        cyf_post_result post;

        memset(&post, 0, sizeof(post));
        build_propagating_case(
            (uint32_t)message_domain,
            sample_id,
            1u,
            &unmasked,
            &original_share,
            &second_share);
        build_post_context((uint32_t)message_domain, sample_id, &context);

#if CYF_BUILD_MODE == CYF_MODE_STUCK_AT_1
        target_share = (uint16_t)(original_share | CYF_TARGET_MASK);
#else
        target_share = original_share;
#endif

#if CYF_WINDOW_MODE == CYF_WINDOW_EXACT_A2B
        measure_rc = measure_exact_target(
            &group,
            target_share,
            second_share,
            &boolean_share,
            &snapshot);
        if (measure_rc == 0) {
            /* Full propagation oracle remains outside the exact window. */
            cyf_post_fault_target(
                boolean_share,
                second_share,
                context.w_prefix_share0,
                context.w_prefix_share1,
                context.x_prefix_share0,
                context.x_prefix_share1,
                context.x_bit_share0,
                context.x_bit_share1,
                context.r_share0,
                context.r_share1,
                context.secand_mask0,
                context.secand_mask1,
                &post);
        }
#else
        /* A2B and fault establishment are both outside the post window. */
        boolean_share = cyf_a2b_target(target_share, second_share);
        measure_rc = measure_post_target(
            &group,
            boolean_share,
            second_share,
            &context,
            &post,
            &snapshot);
#endif
        if (measure_rc != 0) {
            snapshot.error_code = measure_rc;
        }

        oracle_success = semantic_check(
            unmasked,
            original_share,
            target_share,
            second_share,
            boolean_share,
            &post,
            fault_requested,
            &fault_applied,
            &stuck_at_one,
            &a2b_relation,
            &propagated_to_msb,
            &propagated_to_compare_bit,
            &predicted_failure,
            &observed_unmasked,
            &decoded_before,
            &decoded_after,
            &compare_before,
            &compare_after);

        semantic_valid = oracle_success && snapshot.error_code == 0;
        running_percent =
            snapshot.time_enabled == 0u
                ? 0.0
                : 100.0 * (double)snapshot.time_running /
                  (double)snapshot.time_enabled;

        fprintf(
            out,
            "%lu,%s,%s,0x%08lx,1,%lu,%lu,%lu,"
            "%lu,%lu,%lu,%lu,%lu,"
            "%lu,%u,"
            "0x%04x,0x%04x,0x%04x,0x%04x,"
            "0x%04x,0x%04x,"
            "%u,%u,%u,%u,%u,%u,"
            "0x%08" PRIx32 ",0x%08" PRIx32 ",0x%08" PRIx32 ",%u,"
            "%d,%d,%d,%d,%d,%d,%d,%d,%d,"
            "%d,%" PRIu64 ",%" PRIu64 ",%.6f,"
            "0x%08" PRIx32 ",0x%08" PRIx32 ",0x%08" PRIx32 ","
            "0x%08" PRIx32 ",%" PRId32,
            (unsigned long)sample_id,
            fault_requested ? "stuck-at-1" : "baseline",
            window_name(),
            message_domain,
            collection_block,
            collection_round,
            collection_order,
            experiment_run,
            experiment_seed,
            pair_kind,
            pair_order,
            pair_position,
            target_coeff,
            CYF_TARGET_BIT,
            unmasked,
            original_share,
            target_share,
            second_share,
            boolean_share,
            observed_unmasked,
            (unsigned int)((original_share >> CYF_TARGET_BIT) & 1u),
            (unsigned int)((target_share >> CYF_TARGET_BIT) & 1u),
            decoded_before,
            decoded_after,
            compare_before,
            compare_after,
            post.unmasked_w,
            post.unmasked_x,
            post.unmasked_compare,
            (unsigned int)post.comparison_failure,
            fault_requested,
            fault_applied,
            stuck_at_one,
            a2b_relation,
            propagated_to_msb,
            propagated_to_compare_bit,
            predicted_failure,
            oracle_success,
            semantic_valid,
            CYF_COUNTER_SET,
            snapshot.time_enabled,
            snapshot.time_running,
            running_percent,
            snapshot.requested_mask,
            snapshot.available_mask,
            snapshot.open_error_mask,
            snapshot.valid_mask,
            snapshot.error_code);

        for (event_index = 0; event_index < CYF_EVENT_COUNT; ++event_index) {
            fprintf(out, ",%" PRIu64, snapshot.counters[event_index]);
        }
        fputc('\n', out);

        if (!semantic_valid) {
            fprintf(
                stderr,
                "[error] semantic/PMU validation failed for sample %lu "
                "(window=%s error=%d requested=0x%08" PRIx32
                " available=0x%08" PRIx32
                " open_error=0x%08" PRIx32
                " valid=0x%08" PRIx32 ")\n",
                (unsigned long)sample_id,
                window_name(),
                snapshot.error_code,
                snapshot.requested_mask,
                snapshot.available_mask,
                snapshot.open_error_mask,
                snapshot.valid_mask);
            fclose(out);
            close_perf_group(&group);
            return EXIT_FAILURE;
        }
    }

    if (fflush(out) != 0 || fclose(out) != 0) {
        perror("close output");
        out = NULL;
        goto cleanup;
    }
    out = NULL;
    ret = EXIT_SUCCESS;

cleanup:
    if (out != NULL) {
        fclose(out);
    }
    close_perf_group(&group);
    return ret;
}
