#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "breaking_the_shield_x86.h"

#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef BTS_REGION
#define BTS_REGION 1
#endif

#ifndef BTS_ATTACK
#define BTS_ATTACK 0
#endif

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

static void build_input(uint8_t *input, size_t length, uint64_t domain, uint64_t sample)
{
    uint64_t state =
        domain ^
        (sample * UINT64_C(0xd1342543de82ef95)) ^
        UINT64_C(0x425245414b534849);
    size_t i;

    for (i = 0; i < length; i += 8u) {
        uint64_t value = splitmix64(&state);
        size_t remain = length - i;
        memcpy(input + i, &value, remain < 8u ? remain : 8u);
    }
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

static const char *mode_name(void)
{
    return BTS_ATTACK ? "attack" : "baseline";
}

static const char *region_name(void)
{
#if BTS_REGION == 1
    return "shake256-absorb-bne-skip";
#else
    return "polyz-unpack-ldr-skip-zero";
#endif
}

static unsigned int expected_blocks(void)
{
#if BTS_REGION == 1
    return BTS_ATTACK ?
        BTS_SHAKE_ABORT_AFTER_BLOCKS :
        BTS_SHAKE_FULL_BLOCKS;
#else
    return 0u;
#endif
}

static int semantic_case(uint64_t domain, uint64_t sample)
{
    bts_result measured;
    bts_result expected;
    bts_job job;

#if BTS_REGION == 1
    uint8_t input[BTS_SHAKE_INPUT_BYTES];

    build_input(input, sizeof(input), domain, sample);
    memset(&measured, 0, sizeof(measured));
    memset(&expected, 0, sizeof(expected));

    job.input = input;
    job.output = &measured;
    bts_target(&job);

    bts_reference_shake(
        expected.shake,
        input,
        expected_blocks());

    return memcmp(
        measured.shake,
        expected.shake,
        BTS_SHAKE_OUTPUT_BYTES) == 0;
#else
    uint8_t input[BTS_POLYZ_GROUP_BYTES];
    int32_t canonical;

    build_input(input, sizeof(input), domain, sample);

    /*
     * Ensure the loaded 18-bit field is nonzero so the skipped-load output
     * differs from the canonical coefficient.
     */
    input[2] |= UINT8_C(0x04);

    measured.coefficient = 0;
    job.input = input;
    job.output = &measured;

    /* Direct semantic self-test: establish the ARM-r5 analogue as zero. */
    __asm__ __volatile__(
        "xorl %%r12d, %%r12d"
        :
        :
        : "r12", "cc");
    bts_target(&job);

    expected.coefficient =
        bts_reference_polyz_coefficient(input, BTS_ATTACK);
    canonical =
        bts_reference_polyz_coefficient(input, 0);

    if (measured.coefficient != expected.coefficient) {
        return 0;
    }
    if (BTS_ATTACK &&
        measured.coefficient == canonical) {
        return 0;
    }
    return 1;
#endif
}

static void write_header(FILE *out)
{
    fprintf(
        out,
        "sample,region,mode,semantic_valid,expected_blocks,"
        "output_tag,expected_tag,canonical_tag,"
        "cpu_before,cpu_after,cpu_stable,"
        "time_enabled,time_running,running_percent,"
        "requested_mask,available_mask,valid_mask,error_code,"
        "%s,%s\n",
        bts_event_name(0),
        bts_event_name(1));
}

int main(int argc, char **argv)
{
    const char *output_path = NULL;
    unsigned long samples = 500u;
    unsigned long warmup = 20u;
    unsigned long sample_offset = 0u;
    unsigned long domain = UINT64_C(0x42545331);
    int cpu = -1;
    int self_test = 0;
    unsigned long arg;
    unsigned long i;
    FILE *out;

    for (arg = 1; arg < (unsigned long)argc; ++arg) {
        if (strcmp(argv[arg], "--samples") == 0 &&
            arg + 1 < (unsigned long)argc) {
            samples = parse_ulong(argv[++arg], "samples");
        } else if (strcmp(argv[arg], "--warmup") == 0 &&
                   arg + 1 < (unsigned long)argc) {
            warmup = parse_ulong(argv[++arg], "warmup");
        } else if (strcmp(argv[arg], "--sample-offset") == 0 &&
                   arg + 1 < (unsigned long)argc) {
            sample_offset =
                parse_ulong(argv[++arg], "sample-offset");
        } else if (strcmp(argv[arg], "--domain") == 0 &&
                   arg + 1 < (unsigned long)argc) {
            domain = parse_ulong(argv[++arg], "domain");
        } else if (strcmp(argv[arg], "--cpu") == 0 &&
                   arg + 1 < (unsigned long)argc) {
            cpu = (int)parse_ulong(argv[++arg], "cpu");
        } else if (strcmp(argv[arg], "--output") == 0 &&
                   arg + 1 < (unsigned long)argc) {
            output_path = argv[++arg];
        } else if (strcmp(argv[arg], "--self-test") == 0) {
            self_test = 1;
        } else {
            fprintf(
                stderr,
                "usage: %s [--self-test] [--samples N] "
                "[--warmup N] [--sample-offset N] "
                "[--domain N] [--cpu N] [--output FILE]\n",
                argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (self_test) {
        for (i = 0; i < 1000u; ++i) {
            if (!semantic_case(
                    UINT64_C(0x53454d414e544943),
                    i)) {
                fprintf(
                    stderr,
                    "[error] semantic self-test failed: "
                    "region=%s mode=%s sample=%lu\n",
                    region_name(),
                    mode_name(),
                    i);
                return EXIT_FAILURE;
            }
        }
        printf(
            "semantic self-test passed: region=%s mode=%s "
            "cases=1000\n",
            region_name(),
            mode_name());
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
    if (bts_hpc_init() != 0) {
        perror("[error] bts_hpc_init");
        return EXIT_FAILURE;
    }

    out = fopen(output_path, "w");
    if (out == NULL) {
        perror("[error] fopen");
        bts_hpc_close();
        return EXIT_FAILURE;
    }
    write_header(out);

    for (i = 0; i < warmup; ++i) {
        (void)semantic_case(
            domain ^ UINT64_C(0x5741524d),
            i);
    }

    for (i = 0; i < samples; ++i) {
        uint64_t sample = sample_offset + i;
        bts_result measured;
        bts_result expected;
        bts_result canonical;
        bts_job job;
        bts_hpc_snapshot snapshot;
        int semantic_valid;
        int cpu_before;
        int cpu_after;
        uint64_t output_tag;
        uint64_t expected_tag;
        uint64_t canonical_tag;
        double running_percent = 0.0;

#if BTS_REGION == 1
        uint8_t input[BTS_SHAKE_INPUT_BYTES];

        build_input(input, sizeof(input), domain, sample);
        memset(&measured, 0, sizeof(measured));
        memset(&expected, 0, sizeof(expected));
        memset(&canonical, 0, sizeof(canonical));

        job.input = input;
        job.output = &measured;

        bts_reference_shake(
            expected.shake,
            input,
            expected_blocks());
        bts_reference_shake(
            canonical.shake,
            input,
            BTS_SHAKE_FULL_BLOCKS);

        cpu_before = sched_getcpu();
        bts_measure_target(&job);
        cpu_after = sched_getcpu();

        semantic_valid =
            memcmp(
                measured.shake,
                expected.shake,
                BTS_SHAKE_OUTPUT_BYTES) == 0;
        if (BTS_ATTACK &&
            memcmp(
                measured.shake,
                canonical.shake,
                BTS_SHAKE_OUTPUT_BYTES) == 0) {
            semantic_valid = 0;
        }

        output_tag =
            tag_bytes(measured.shake, BTS_SHAKE_OUTPUT_BYTES);
        expected_tag =
            tag_bytes(expected.shake, BTS_SHAKE_OUTPUT_BYTES);
        canonical_tag =
            tag_bytes(canonical.shake, BTS_SHAKE_OUTPUT_BYTES);
#else
        uint8_t input[BTS_POLYZ_GROUP_BYTES];

        build_input(input, sizeof(input), domain, sample);
        input[2] |= UINT8_C(0x04);

        measured.coefficient = 0;
        expected.coefficient =
            bts_reference_polyz_coefficient(input, BTS_ATTACK);
        canonical.coefficient =
            bts_reference_polyz_coefficient(input, 0);

        job.input = input;
        job.output = &measured;

        cpu_before = sched_getcpu();
        bts_measure_target(&job);
        cpu_after = sched_getcpu();

        semantic_valid =
            measured.coefficient == expected.coefficient;
        if (BTS_ATTACK &&
            measured.coefficient == canonical.coefficient) {
            semantic_valid = 0;
        }

        output_tag =
            (uint64_t)(uint32_t)measured.coefficient;
        expected_tag =
            (uint64_t)(uint32_t)expected.coefficient;
        canonical_tag =
            (uint64_t)(uint32_t)canonical.coefficient;
#endif

        bts_get_hpc_snapshot(&snapshot);
        if (snapshot.time_enabled != 0u) {
            running_percent =
                100.0 *
                (double)snapshot.time_running /
                (double)snapshot.time_enabled;
        }

        fprintf(
            out,
            "%" PRIu64 ",%s,%s,%d,%u,"
            "0x%016" PRIx64 ",0x%016" PRIx64 ",0x%016" PRIx64 ","
            "%d,%d,%d,%" PRIu64 ",%" PRIu64 ",%.6f,"
            "0x%08" PRIx32 ",0x%08" PRIx32 ",0x%08" PRIx32 ","
            "%" PRId32 ",%" PRIu64 ",%" PRIu64 "\n",
            sample,
            region_name(),
            mode_name(),
            semantic_valid,
            expected_blocks(),
            output_tag,
            expected_tag,
            canonical_tag,
            cpu_before,
            cpu_after,
            cpu_before == cpu_after && cpu_before == cpu,
            snapshot.time_enabled,
            snapshot.time_running,
            running_percent,
            snapshot.requested_mask,
            snapshot.available_mask,
            snapshot.valid_mask,
            snapshot.error_code,
            snapshot.values[0],
            snapshot.values[1]);
    }

    fclose(out);
    bts_hpc_close();
    return EXIT_SUCCESS;
}
