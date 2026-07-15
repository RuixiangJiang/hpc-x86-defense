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

#define MFK_VARIANT_ABORT_BASELINE 0
#define MFK_VARIANT_LOOP_ABORT 1
#define MFK_VARIANT_SKIP_BASELINE 2
#define MFK_VARIANT_SKIP_ROUND 3

#ifndef MFK_VARIANT
#define MFK_VARIANT MFK_VARIANT_ABORT_BASELINE
#endif

#ifndef MFK_ATTACK_ROUNDS
#define MFK_ATTACK_ROUNDS 8
#endif

#ifndef MFK_SKIP_ROUND
#define MFK_SKIP_ROUND 8
#endif

#define MFK_MESSAGE_BYTES 64u
#define MFK_SHAKE256_RATE 136u
#define MFK_OUTPUT_BYTES 64u

static const uint64_t ref_round_constants[24] = {
    UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
    UINT64_C(0x800000000000808a), UINT64_C(0x8000000080008000),
    UINT64_C(0x000000000000808b), UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
    UINT64_C(0x000000000000008a), UINT64_C(0x0000000000000088),
    UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000a),
    UINT64_C(0x000000008000808b), UINT64_C(0x800000000000008b),
    UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
    UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
    UINT64_C(0x000000000000800a), UINT64_C(0x800000008000000a),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
    UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008)
};

static const unsigned int ref_rotation[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const unsigned int ref_pilane[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

static uint64_t rol64(uint64_t x, unsigned int shift) {
    return (x << shift) | (x >> (64u - shift));
}

static void reference_round(uint64_t state[25], unsigned int round) {
    uint64_t bc[5];
    uint64_t t;
    unsigned int i;
    unsigned int j;

    for (i = 0; i < 5; ++i) {
        bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^
                state[i + 15] ^ state[i + 20];
    }
    for (i = 0; i < 5; ++i) {
        t = bc[(i + 4) % 5] ^ rol64(bc[(i + 1) % 5], 1);
        for (j = 0; j < 25; j += 5) {
            state[j + i] ^= t;
        }
    }
    t = state[1];
    for (i = 0; i < 24; ++i) {
        j = ref_pilane[i];
        bc[0] = state[j];
        state[j] = rol64(t, ref_rotation[i]);
        t = bc[0];
    }
    for (j = 0; j < 25; j += 5) {
        for (i = 0; i < 5; ++i) {
            bc[i] = state[j + i];
        }
        for (i = 0; i < 5; ++i) {
            state[j + i] =
                bc[i] ^ ((~bc[(i + 1) % 5]) & bc[(i + 2) % 5]);
        }
    }
    state[0] ^= ref_round_constants[round];
}

static void reference_prefix(uint64_t state[25], unsigned int rounds) {
    unsigned int round;
    for (round = 0; round < rounds; ++round) {
        reference_round(state, round);
    }
}

static void reference_skip_round(uint64_t state[25], unsigned int skipped) {
    unsigned int round;
    for (round = 0; round < 24u; ++round) {
        if (round != skipped) {
            reference_round(state, round);
        }
    }
}

static unsigned long parse_ulong(const char *text, const char *name) {
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

static int bind_to_cpu(int cpu) {
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
    if (sched_getcpu() != cpu) {
        errno = EXDEV;
        return -1;
    }
    return 0;
}

static uint64_t splitmix64(uint64_t *state) {
    uint64_t z = (*state += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

static void build_message(uint8_t message[MFK_MESSAGE_BYTES],
                          uint64_t domain,
                          uint64_t sample) {
    uint64_t state =
        domain ^ (sample * UINT64_C(0xd1342543de82ef95)) ^
        UINT64_C(0x4d696e645f4b4543);
    size_t i;
    for (i = 0; i < MFK_MESSAGE_BYTES; i += 8) {
        uint64_t value = splitmix64(&state);
        size_t j;
        for (j = 0; j < 8; ++j) {
            message[i + j] = (uint8_t)(value >> (8u * j));
        }
    }
}

static void xor_state_byte(uint64_t state[25], size_t index, uint8_t value) {
    state[index >> 3] ^= (uint64_t)value << (8u * (index & 7u));
}

static void prepare_shake256_state(uint64_t state[25],
                                   const uint8_t message[MFK_MESSAGE_BYTES]) {
    size_t i;
    memset(state, 0, 25u * sizeof(uint64_t));
    for (i = 0; i < MFK_MESSAGE_BYTES; ++i) {
        xor_state_byte(state, i, message[i]);
    }
    xor_state_byte(state, MFK_MESSAGE_BYTES, UINT8_C(0x1f));
    xor_state_byte(state, MFK_SHAKE256_RATE - 1u, UINT8_C(0x80));
}

static uint64_t output_tag(const uint64_t state[25]) {
    uint64_t hash = UINT64_C(1469598103934665603);
    size_t i;
    for (i = 0; i < MFK_OUTPUT_BYTES; ++i) {
        uint8_t byte = (uint8_t)(state[i >> 3] >> (8u * (i & 7u)));
        hash ^= byte;
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static void build_oracle(uint64_t state[25]) {
#if MFK_VARIANT == MFK_VARIANT_LOOP_ABORT
    reference_prefix(state, (unsigned int)MFK_ATTACK_ROUNDS);
#elif MFK_VARIANT == MFK_VARIANT_SKIP_ROUND
    reference_skip_round(state, (unsigned int)MFK_SKIP_ROUND);
#else
    reference_prefix(state, 24u);
#endif
}

static int run_semantic_case(uint64_t domain, uint64_t sample) {
    uint8_t message[MFK_MESSAGE_BYTES];
    uint64_t initial[25];
    uint64_t target[25];
    uint64_t expected[25];
    uint64_t full[25];

    build_message(message, domain, sample);
    prepare_shake256_state(initial, message);
    memcpy(target, initial, sizeof(target));
    memcpy(expected, initial, sizeof(expected));
    memcpy(full, initial, sizeof(full));

    mfk_keccak_target(target);
    build_oracle(expected);
    reference_prefix(full, 24u);

    if (memcmp(target, expected, sizeof(target)) != 0) {
        return 0;
    }
#if MFK_VARIANT == MFK_VARIANT_LOOP_ABORT || \
    MFK_VARIANT == MFK_VARIANT_SKIP_ROUND
    if (memcmp(target, full, sizeof(target)) == 0) {
        return 0;
    }
#else
    if (memcmp(target, full, sizeof(target)) != 0) {
        return 0;
    }
#endif
    return 1;
}

static void write_header(FILE *out) {
    unsigned int i;
    fputs(
        "sample,attack_family,mode,input_domain,target_rounds,full_rounds,"
        "abort_rounds,skipped_round,semantic_valid,oracle_match,"
        "fault_output_differs_full,output_tag,affinity_cpu,cpu_before,"
        "cpu_after,cpu_stable,sequence,time_enabled,time_running,"
        "running_percent,requested_mask,available_mask,open_error_mask,"
        "valid_mask,error_code",
        out);
    for (i = 0; i < MFK_HPC_EVENT_COUNT; ++i) {
        fprintf(out, ",%s", mfk_event_name(i));
    }
    fputc('\n', out);
}

int main(int argc, char **argv) {
    const char *output_path = NULL;
    unsigned long samples = 500;
    unsigned long warmup = 20;
    unsigned long domain = UINT64_C(0x4d464b31);
    int self_test = 0;
    int affinity_cpu = -1;
    unsigned long arg;
    FILE *out = NULL;
    unsigned long i;

    for (arg = 1; arg < (unsigned long)argc; ++arg) {
        if (strcmp(argv[arg], "--samples") == 0 &&
            arg + 1 < (unsigned long)argc) {
            samples = parse_ulong(argv[++arg], "samples");
        } else if (strcmp(argv[arg], "--warmup") == 0 &&
                   arg + 1 < (unsigned long)argc) {
            warmup = parse_ulong(argv[++arg], "warmup");
        } else if (strcmp(argv[arg], "--domain") == 0 &&
                   arg + 1 < (unsigned long)argc) {
            domain = parse_ulong(argv[++arg], "domain");
        } else if (strcmp(argv[arg], "--output") == 0 &&
                   arg + 1 < (unsigned long)argc) {
            output_path = argv[++arg];
        } else if (strcmp(argv[arg], "--cpu") == 0 &&
                   arg + 1 < (unsigned long)argc) {
            affinity_cpu = (int)parse_ulong(argv[++arg], "CPU");
        } else if (strcmp(argv[arg], "--self-test") == 0) {
            self_test = 1;
        } else {
            fprintf(stderr,
                    "usage: %s [--self-test] [--samples N] [--warmup N] "
                    "[--domain N] [--cpu N] [--output FILE]\n",
                    argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (self_test) {
        for (i = 0; i < 1000; ++i) {
            if (!run_semantic_case(UINT64_C(0x53454d41), i)) {
                fprintf(stderr, "[error] semantic self-test failed at %lu\n", i);
                return EXIT_FAILURE;
            }
        }
        printf(
            "semantic self-test passed: family=%s mode=%s rounds=%u "
            "abort_rounds=%u skipped_round=%d cases=1000\n",
            mfk_attack_family(),
            mfk_mode_name(),
            mfk_target_rounds(),
            mfk_abort_rounds(),
            mfk_skipped_round());
        return EXIT_SUCCESS;
    }

    if (output_path == NULL || samples == 0) {
        fprintf(stderr, "[error] --output and samples > 0 are required\n");
        return EXIT_FAILURE;
    }
    if (affinity_cpu < 0) {
        fprintf(stderr,
                "[error] --cpu is required for PMU collection; "
                "run through run.sh or set MFK_CPU_CORE\n");
        return EXIT_FAILURE;
    }
    if (bind_to_cpu(affinity_cpu) != 0) {
        fprintf(stderr, "[error] unable to bind to CPU %d: %s\n",
                affinity_cpu, strerror(errno));
        return EXIT_FAILURE;
    }

    for (i = 0; i < warmup; ++i) {
        uint8_t message[MFK_MESSAGE_BYTES];
        uint64_t state[25];
        build_message(message, domain ^ UINT64_C(0x57524d55), i);
        prepare_shake256_state(state, message);
        mfk_keccak_target(state);
    }

    {
        int rc = mfk_hpc_init();
        if (rc != 0) {
            fprintf(stderr,
                    "[error] perf_event_open initialization failed: %s (%d)\n",
                    strerror(-rc), rc);
            fprintf(stderr,
                    "[hint] check perf_event_paranoid, raw-event access, "
                    "and CPU affinity/P-core selection\n");
            return EXIT_FAILURE;
        }
    }

    out = fopen(output_path, "w");
    if (out == NULL) {
        perror("open output");
        mfk_hpc_close();
        return EXIT_FAILURE;
    }
    write_header(out);

    for (i = 0; i < samples; ++i) {
        uint8_t message[MFK_MESSAGE_BYTES];
        uint64_t initial[25];
        uint64_t measured[25];
        uint64_t oracle[25];
        uint64_t full[25];
        mfk_hpc_snapshot snap;
        int oracle_match;
        int differs_full;
        int semantic_valid;
        double running_percent;
        unsigned int event_index;
        int cpu_before;
        int cpu_after;
        int cpu_stable;

        build_message(message, (uint64_t)domain, i);
        prepare_shake256_state(initial, message);
        memcpy(measured, initial, sizeof(measured));
        memcpy(oracle, initial, sizeof(oracle));
        memcpy(full, initial, sizeof(full));

        cpu_before = sched_getcpu();
        mfk_measure_target(measured);
        cpu_after = sched_getcpu();
        cpu_stable =
            cpu_before == affinity_cpu && cpu_after == affinity_cpu;
        mfk_get_hpc_snapshot(&snap);

        build_oracle(oracle);
        reference_prefix(full, 24u);
        oracle_match = memcmp(measured, oracle, sizeof(measured)) == 0;
        differs_full = memcmp(measured, full, sizeof(measured)) != 0;

#if MFK_VARIANT == MFK_VARIANT_LOOP_ABORT || \
    MFK_VARIANT == MFK_VARIANT_SKIP_ROUND
        semantic_valid = oracle_match && differs_full;
#else
        semantic_valid = oracle_match && !differs_full;
#endif

        running_percent =
            snap.time_enabled == 0
                ? 0.0
                : 100.0 * (double)snap.time_running /
                      (double)snap.time_enabled;

        fprintf(
            out,
            "%lu,%s,%s,0x%016" PRIx64 ",%u,24,%u,%d,%d,%d,%d,"
            "0x%016" PRIx64 ",%d,%d,%d,%d,"
            "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%.6f,"
            "0x%08" PRIx32 ",0x%08" PRIx32 ",0x%08" PRIx32 ","
            "0x%08" PRIx32 ",%" PRId32,
            i,
            mfk_attack_family(),
            mfk_mode_name(),
            (uint64_t)domain,
            mfk_target_rounds(),
            mfk_abort_rounds(),
            mfk_skipped_round(),
            semantic_valid,
            oracle_match,
            differs_full,
            output_tag(measured),
            affinity_cpu,
            cpu_before,
            cpu_after,
            cpu_stable,
            snap.sequence,
            snap.time_enabled,
            snap.time_running,
            running_percent,
            snap.requested_mask,
            snap.available_mask,
            snap.open_error_mask,
            snap.valid_mask,
            snap.error_code);

        for (event_index = 0; event_index < MFK_HPC_EVENT_COUNT; ++event_index) {
            fprintf(out, ",%" PRIu64, snap.values[event_index]);
        }
        fputc('\n', out);

        if (!semantic_valid) {
            fprintf(stderr, "[error] semantic validation failed at sample %lu\n", i);
            fclose(out);
            mfk_hpc_close();
            return EXIT_FAILURE;
        }
    }

    fclose(out);
    mfk_hpc_close();
    return EXIT_SUCCESS;
}
