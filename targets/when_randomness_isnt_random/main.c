#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "when_randomness_isnt_random_x86.h"

#include <errno.h>
#include <immintrin.h>
#include <inttypes.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WRIR_REGION
#define WRIR_REGION 1
#endif

#ifndef WRIR_ATTACK
#define WRIR_ATTACK 0
#endif

#define PAGE_BYTES 4096u
#define COINS_BYTES 32u
#define SIGMA_BYTES 64u
#define NOISESEED_OFFSET 32u

_Alignas(PAGE_BYTES) static uint8_t correct_page[PAGE_BYTES];
_Alignas(PAGE_BYTES) static uint8_t fault_page[PAGE_BYTES];
static volatile uint8_t cache_sink;

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

static int bind_to_cpu(int cpu)
{
    cpu_set_t set;

    if (cpu < 0 || cpu >= CPU_SETSIZE) {
        errno = EINVAL;
        return -1;
    }
    CPU_ZERO(&set);
    CPU_SET((unsigned int)cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        return -1;
    }
    return sched_getcpu() == cpu ? 0 : -1;
}

static uint64_t splitmix64(uint64_t *state)
{
    uint64_t z = (*state += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

static void fill_correct(uint64_t domain, uint64_t sample, size_t length)
{
    uint64_t state =
        domain ^ (sample * UINT64_C(0xd1342543de82ef95));
    size_t i;

    for (i = 0; i < length; i += 8u) {
        uint64_t value = splitmix64(&state);
        size_t remain = length - i;
        memcpy(correct_page + i, &value, remain < 8u ? remain : 8u);
    }
}

static void initialize_fault_page(void)
{
    size_t i;
#if WRIR_REGION == 2
    for (i = 0; i < PAGE_BYTES; ++i) {
        fault_page[i] = (uint8_t)(UINT8_C(0xa5) ^ (uint8_t)(13u * i));
    }
#elif WRIR_REGION == 3
    memset(fault_page, 0x5c, PAGE_BYTES);
#else
    memset(fault_page, 0, PAGE_BYTES);
#endif
}

static uint64_t tag_bytes(const uint8_t *data, size_t length)
{
    uint64_t hash = UINT64_C(1469598103934665603);
    size_t i;

    for (i = 0; i < length; ++i) {
        hash ^= data[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static void touch_lines(const uint8_t *data, size_t length)
{
    size_t i;
    uint8_t value = 0;
    for (i = 0; i < length; i += 64u) {
        value ^= data[i];
    }
    cache_sink ^= value;
}

static void flush_lines(const uint8_t *data, size_t length)
{
    size_t i;
    for (i = 0; i < length; i += 64u) {
        _mm_clflush(data + i);
    }
    _mm_mfence();
}

static int prepare_cache_profile(
    const char *profile,
    size_t length)
{
#if WRIR_REGION == 1
    (void)profile;
    (void)length;
    return 0;
#else
    if (strcmp(profile, "matched-hot") == 0) {
        touch_lines(correct_page, length);
        touch_lines(fault_page, length);
        return 0;
    }
    if (strcmp(profile, "redirect-cold") == 0) {
        touch_lines(correct_page, length);
        flush_lines(fault_page, length);
        return 0;
    }
    fprintf(stderr, "[error] unknown cache profile: %s\n", profile);
    return -1;
#endif
}

static const char *mode_name(void)
{
    return WRIR_ATTACK ? "attack" : "baseline";
}

static size_t region_length(void)
{
#if WRIR_REGION == 1
    return NOISESEED_OFFSET + SIGMA_BYTES;
#elif WRIR_REGION == 2
    return COINS_BYTES;
#else
    return SIGMA_BYTES;
#endif
}

static int semantic_case(
    uint64_t domain,
    uint64_t sample,
    const char *profile)
{
    uint8_t output[SIGMA_BYTES] = {0};
    size_t length = region_length();

    fill_correct(domain, sample, length);
    if (prepare_cache_profile(profile, length) != 0) {
        return 0;
    }

#if WRIR_REGION == 1
    const uint8_t *used = NULL;
    const uint8_t *expected =
        WRIR_ATTACK ? correct_page : correct_page + NOISESEED_OFFSET;
    wrir_target(correct_page, &used);
    return used == expected;
#else
    wrir_pointer_frame frame;
    const uint8_t *expected = WRIR_ATTACK ? fault_page : correct_page;
    frame.correct = correct_page;
    frame.fault = fault_page;
    wrir_target(&frame, output);
    return memcmp(output, expected, length) == 0;
#endif
}

static void write_header(FILE *out)
{
    fprintf(
        out,
        "sample,region,mode,cache_profile,semantic_valid,"
        "fault_applied,correct_tag,fault_tag,output_tag,"
        "cpu_before,cpu_after,cpu_stable,time_enabled,time_running,"
        "running_percent,requested_mask,available_mask,valid_mask,"
        "error_code,%s,%s\n",
        wrir_event_name(0),
        wrir_event_name(1));
}

int main(int argc, char **argv)
{
    const char *output_path = NULL;
    const char *profile = "matched-hot";
    unsigned long samples = 500u;
    unsigned long warmup = 20u;
    unsigned long sample_offset = 0u;
    unsigned long domain = UINT64_C(0x57524952);
    int cpu = -1;
    int self_test = 0;
    unsigned long arg;
    unsigned long i;
    FILE *out;
    size_t length = region_length();

    for (arg = 1; arg < (unsigned long)argc; ++arg) {
        if (strcmp(argv[arg], "--samples") == 0 &&
            arg + 1 < (unsigned long)argc) {
            samples = parse_ulong(argv[++arg], "samples");
        } else if (strcmp(argv[arg], "--warmup") == 0 &&
                   arg + 1 < (unsigned long)argc) {
            warmup = parse_ulong(argv[++arg], "warmup");
        } else if (strcmp(argv[arg], "--sample-offset") == 0 &&
                   arg + 1 < (unsigned long)argc) {
            sample_offset = parse_ulong(argv[++arg], "sample-offset");
        } else if (strcmp(argv[arg], "--domain") == 0 &&
                   arg + 1 < (unsigned long)argc) {
            domain = parse_ulong(argv[++arg], "domain");
        } else if (strcmp(argv[arg], "--cpu") == 0 &&
                   arg + 1 < (unsigned long)argc) {
            cpu = (int)parse_ulong(argv[++arg], "cpu");
        } else if (strcmp(argv[arg], "--cache-profile") == 0 &&
                   arg + 1 < (unsigned long)argc) {
            profile = argv[++arg];
        } else if (strcmp(argv[arg], "--output") == 0 &&
                   arg + 1 < (unsigned long)argc) {
            output_path = argv[++arg];
        } else if (strcmp(argv[arg], "--self-test") == 0) {
            self_test = 1;
        } else {
            fprintf(
                stderr,
                "usage: %s [--self-test] [--samples N] [--warmup N] "
                "[--sample-offset N] [--domain N] [--cpu N] "
                "[--cache-profile matched-hot|redirect-cold] "
                "[--output FILE]\n",
                argv[0]);
            return EXIT_FAILURE;
        }
    }

    initialize_fault_page();

    if (self_test) {
        for (i = 0; i < 1000u; ++i) {
            if (!semantic_case(
                    UINT64_C(0x53454d414e544943),
                    i,
                    profile)) {
                fprintf(
                    stderr,
                    "[error] semantic self-test failed: "
                    "region=%d mode=%s sample=%lu profile=%s\n",
                    WRIR_REGION,
                    mode_name(),
                    i,
                    profile);
                return EXIT_FAILURE;
            }
        }
        printf(
            "semantic self-test passed: region=%d mode=%s "
            "profile=%s cases=1000\n",
            WRIR_REGION,
            mode_name(),
            profile);
        return EXIT_SUCCESS;
    }

    if (output_path == NULL || samples == 0u || cpu < 0) {
        fprintf(
            stderr,
            "[error] collection requires --output, --samples, and --cpu\n");
        return EXIT_FAILURE;
    }
    if (bind_to_cpu(cpu) != 0) {
        perror("[error] sched_setaffinity");
        return EXIT_FAILURE;
    }
    if (wrir_hpc_init() != 0) {
        perror("[error] wrir_hpc_init");
        return EXIT_FAILURE;
    }

    out = fopen(output_path, "w");
    if (out == NULL) {
        perror("[error] fopen");
        wrir_hpc_close();
        return EXIT_FAILURE;
    }
    write_header(out);

    for (i = 0; i < warmup; ++i) {
        (void)semantic_case(
            domain ^ UINT64_C(0x5741524d),
            i,
            profile);
    }

    for (i = 0; i < samples; ++i) {
        uint64_t sample = sample_offset + i;
        uint8_t output[SIGMA_BYTES] = {0};
        wrir_hpc_snapshot snap;
        int cpu_before;
        int cpu_after;
        int semantic_valid;
        uint64_t correct_tag;
        uint64_t fault_tag;
        uint64_t output_tag;
        double running_percent = 0.0;

        fill_correct(domain, sample, length);
        if (prepare_cache_profile(profile, length) != 0) {
            fclose(out);
            wrir_hpc_close();
            return EXIT_FAILURE;
        }

        correct_tag = tag_bytes(correct_page, length);
        fault_tag = tag_bytes(fault_page, length);

#if WRIR_REGION == 1
        const uint8_t *used = NULL;
        const uint8_t *expected =
            WRIR_ATTACK ? correct_page : correct_page + NOISESEED_OFFSET;
        cpu_before = sched_getcpu();
        wrir_measure_target(correct_page, &used);
        cpu_after = sched_getcpu();
        semantic_valid = used == expected;
        output_tag = (uint64_t)(uintptr_t)(used - correct_page);
#else
        wrir_pointer_frame frame;
        const uint8_t *expected = WRIR_ATTACK ? fault_page : correct_page;
        frame.correct = correct_page;
        frame.fault = fault_page;
        cpu_before = sched_getcpu();
        wrir_measure_target(&frame, output);
        cpu_after = sched_getcpu();
        semantic_valid = memcmp(output, expected, length) == 0;
        output_tag = tag_bytes(output, length);
#endif

        wrir_get_hpc_snapshot(&snap);
        if (snap.time_enabled != 0u) {
            running_percent =
                100.0 * (double)snap.time_running /
                (double)snap.time_enabled;
        }

        fprintf(
            out,
            "%" PRIu64 ",%d,%s,%s,%d,%d,"
            "0x%016" PRIx64 ",0x%016" PRIx64 ",0x%016" PRIx64 ","
            "%d,%d,%d,%" PRIu64 ",%" PRIu64 ",%.6f,"
            "0x%08" PRIx32 ",0x%08" PRIx32 ",0x%08" PRIx32 ","
            "%" PRId32 ",%" PRIu64 ",%" PRIu64 "\n",
            sample,
            WRIR_REGION,
            mode_name(),
            profile,
            semantic_valid,
            WRIR_ATTACK,
            correct_tag,
            fault_tag,
            output_tag,
            cpu_before,
            cpu_after,
            cpu_before == cpu_after && cpu_before == cpu,
            snap.time_enabled,
            snap.time_running,
            running_percent,
            snap.requested_mask,
            snap.available_mask,
            snap.valid_mask,
            snap.error_code,
            snap.values[0],
            snap.values[1]);
    }

    fclose(out);
    wrir_hpc_close();
    return EXIT_SUCCESS;
}
