#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "mind_faulty_keccak_x86.h"

#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef MFK_MOVS_SKIP_BUILD
#define MFK_MOVS_SKIP_BUILD 0
#endif

#define MESSAGE_BYTES 64u
#define SHAKE256_RATE 136u
#define OUTPUT_BYTES 64u

static uint64_t splitmix64(uint64_t *state)
{
    uint64_t z = (*state += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
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

static void build_message(uint8_t message[MESSAGE_BYTES],
                          uint64_t domain,
                          uint64_t sample)
{
    uint64_t state =
        domain ^ (sample * UINT64_C(0xd1342543de82ef95)) ^
        UINT64_C(0x4d696e645f4b4543);
    size_t i;
    for (i = 0; i < MESSAGE_BYTES; i += 8) {
        uint64_t value = splitmix64(&state);
        size_t j;
        for (j = 0; j < 8; ++j) {
            message[i + j] = (uint8_t)(value >> (8u * j));
        }
    }
}

static void xor_state_byte(uint64_t state[25], size_t index, uint8_t value)
{
    state[index >> 3] ^= (uint64_t)value << (8u * (index & 7u));
}

static void prepare_state(uint64_t state[25],
                          const uint8_t message[MESSAGE_BYTES])
{
    size_t i;
    memset(state, 0, 25u * sizeof(uint64_t));
    for (i = 0; i < MESSAGE_BYTES; ++i) {
        xor_state_byte(state, i, message[i]);
    }
    xor_state_byte(state, MESSAGE_BYTES, UINT8_C(0x1f));
    xor_state_byte(state, SHAKE256_RATE - 1u, UINT8_C(0x80));
}

static uint64_t output_tag(const uint64_t state[25])
{
    uint64_t hash = UINT64_C(1469598103934665603);
    size_t i;
    for (i = 0; i < OUTPUT_BYTES; ++i) {
        uint8_t byte = (uint8_t)(state[i >> 3] >> (8u * (i & 7u)));
        hash ^= byte;
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static void reference_prefix(uint64_t state[25], unsigned int rounds)
{
    unsigned int round;
    for (round = 0; round < rounds; ++round) {
        mfk_keccak_round(state, round);
    }
}

static unsigned int expected_rounds(void)
{
#if MFK_MOVS_SKIP_BUILD == 1
    return 8u;
#else
    return 24u;
#endif
}

static const char *mode_name(void)
{
#if MFK_MOVS_SKIP_BUILD == 1
    return "movs-skip";
#else
    return "baseline";
#endif
}

static int semantic_case(uint64_t domain, uint64_t sample)
{
    uint8_t message[MESSAGE_BYTES];
    uint64_t target[25];
    uint64_t expected[25];
    uint64_t full[25];

    build_message(message, domain, sample);
    prepare_state(target, message);
    memcpy(expected, target, sizeof(expected));
    memcpy(full, target, sizeof(full));

    mfk_keccak_target(target);
    reference_prefix(expected, expected_rounds());
    reference_prefix(full, 24u);

    if (memcmp(target, expected, sizeof(target)) != 0) {
        return 0;
    }
#if MFK_MOVS_SKIP_BUILD == 1
    return memcmp(target, full, sizeof(target)) != 0;
#else
    return memcmp(target, full, sizeof(target)) == 0;
#endif
}

static void write_header(FILE *out)
{
    fprintf(out,
        "sample,mode,expected_rounds,semantic_valid,"
        "output_differs_full,output_tag,cpu_before,cpu_after,cpu_stable,"
        "time_enabled,time_running,running_percent,requested_mask,"
        "available_mask,open_error_mask,valid_mask,error_code,%s,%s\n",
        mfk_event_name(0), mfk_event_name(1));
}

int main(int argc, char **argv)
{
    const char *output_path = NULL;
    unsigned long samples = 500;
    unsigned long warmup = 20;
    unsigned long sample_offset = 0;
    unsigned long domain = UINT64_C(0x4d464b31);
    int cpu = -1;
    int self_test = 0;
    unsigned long arg;
    FILE *out;
    unsigned long i;

    for (arg = 1; arg < (unsigned long)argc; ++arg) {
        if (strcmp(argv[arg], "--samples") == 0 && arg + 1 < (unsigned long)argc) {
            samples = parse_ulong(argv[++arg], "samples");
        } else if (strcmp(argv[arg], "--warmup") == 0 && arg + 1 < (unsigned long)argc) {
            warmup = parse_ulong(argv[++arg], "warmup");
        } else if (strcmp(argv[arg], "--sample-offset") == 0 && arg + 1 < (unsigned long)argc) {
            sample_offset = parse_ulong(argv[++arg], "sample-offset");
        } else if (strcmp(argv[arg], "--domain") == 0 && arg + 1 < (unsigned long)argc) {
            domain = parse_ulong(argv[++arg], "domain");
        } else if (strcmp(argv[arg], "--cpu") == 0 && arg + 1 < (unsigned long)argc) {
            cpu = (int)parse_ulong(argv[++arg], "cpu");
        } else if (strcmp(argv[arg], "--output") == 0 && arg + 1 < (unsigned long)argc) {
            output_path = argv[++arg];
        } else if (strcmp(argv[arg], "--self-test") == 0) {
            self_test = 1;
        } else {
            fprintf(stderr,
                "usage: %s [--self-test] [--samples N] [--warmup N] "
                "[--sample-offset N] [--domain N] [--cpu N] [--output FILE]\n",
                argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (self_test) {
        for (i = 0; i < 1000; ++i) {
            if (!semantic_case(UINT64_C(0x53454d41), i)) {
                fprintf(stderr,
                    "[error] semantic self-test failed mode=%s sample=%lu\n",
                    mode_name(), i);
                return EXIT_FAILURE;
            }
        }
        printf("semantic self-test passed: mode=%s expected_rounds=%u cases=1000\n",
               mode_name(), expected_rounds());
        return EXIT_SUCCESS;
    }

    if (output_path == NULL || samples == 0 || cpu < 0) {
        fprintf(stderr, "[error] collection requires --output, --samples, and --cpu\n");
        return EXIT_FAILURE;
    }
    if (bind_to_cpu(cpu) != 0) {
        perror("[error] sched_setaffinity");
        return EXIT_FAILURE;
    }
    if (mfk_hpc_init() != 0) {
        perror("[error] mfk_hpc_init");
        return EXIT_FAILURE;
    }

    out = fopen(output_path, "w");
    if (out == NULL) {
        perror("[error] fopen");
        mfk_hpc_close();
        return EXIT_FAILURE;
    }
    write_header(out);

    for (i = 0; i < warmup; ++i) {
        uint8_t message[MESSAGE_BYTES];
        uint64_t state[25];
        build_message(message, domain ^ UINT64_C(0x5741524d), i);
        prepare_state(state, message);
        mfk_keccak_target(state);
    }

    for (i = 0; i < samples; ++i) {
        uint64_t sample = sample_offset + i;
        uint8_t message[MESSAGE_BYTES];
        uint64_t target[25];
        uint64_t expected[25];
        uint64_t full[25];
        mfk_hpc_snapshot snapshot;
        int cpu_before;
        int cpu_after;
        int semantic_valid;
        int differs_full;
        double running_percent = 0.0;

        build_message(message, domain, sample);
        prepare_state(target, message);
        memcpy(expected, target, sizeof(expected));
        memcpy(full, target, sizeof(full));
        reference_prefix(expected, expected_rounds());
        reference_prefix(full, 24u);

        cpu_before = sched_getcpu();
        mfk_measure_target(target);
        cpu_after = sched_getcpu();
        mfk_get_hpc_snapshot(&snapshot);

        semantic_valid = memcmp(target, expected, sizeof(target)) == 0;
        differs_full = memcmp(target, full, sizeof(target)) != 0;
        if (snapshot.time_enabled != 0) {
            running_percent = 100.0 * (double)snapshot.time_running /
                              (double)snapshot.time_enabled;
        }

        fprintf(
            out,
            "%" PRIu64 ",%s,%u,%d,%d,0x%016" PRIx64
            ",%d,%d,%d,%" PRIu64 ",%" PRIu64 ",%.6f,"
            "0x%08" PRIx32 ",0x%08" PRIx32 ",0x%08" PRIx32
            ",0x%08" PRIx32 ",%" PRId32 ",%" PRIu64
            ",%" PRIu64 "\n",
            sample,
            mode_name(),
            expected_rounds(),
            semantic_valid,
            differs_full,
            output_tag(target),
            cpu_before,
            cpu_after,
            cpu_before == cpu_after && cpu_before == cpu,
            snapshot.time_enabled,
            snapshot.time_running,
            running_percent,
            snapshot.requested_mask,
            snapshot.available_mask,
            snapshot.open_error_mask,
            snapshot.valid_mask,
            snapshot.error_code,
            snapshot.values[0],
            snapshot.values[1]);
    }

    fclose(out);
    mfk_hpc_close();
    return EXIT_SUCCESS;
}
