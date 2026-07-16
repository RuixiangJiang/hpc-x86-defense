#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "secret_in_onepiece_x86.h"

#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    SIO_MODE_UNSET = 0,
    SIO_MODE_BASELINE = 1,
    SIO_MODE_ATTACK = 2,
} sio_mode;

typedef enum {
    SIO_FAMILY_INVALID = 0,
    SIO_FAMILY_SKIP_ASSIGNMENT,
    SIO_FAMILY_SKIP_OR,
} sio_family;

typedef struct {
    sio_family family;
    sio_mode mode;
    const char *family_label;
    sio_target_fn selected_target;
    sio_target_fn intended_target;
    sio_target_fn fault_target;
    sio_measure_fn selected_measure;
    int assignment_executed;
    int or_executed;
} sio_case;

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

static sio_family parse_family(const char *label) {
    if (strcmp(label, "skip-bit-assignment") == 0) {
        return SIO_FAMILY_SKIP_ASSIGNMENT;
    }
    if (strcmp(label, "skip-or-operation") == 0) {
        return SIO_FAMILY_SKIP_OR;
    }
    return SIO_FAMILY_INVALID;
}

static sio_case prepare_case(const char *label, sio_mode mode) {
    sio_case selected;
    memset(&selected, 0, sizeof(selected));
    selected.family = parse_family(label);
    selected.mode = mode;
    selected.family_label = label;
    selected.intended_target = sio_decoder_baseline_target;

    switch (selected.family) {
    case SIO_FAMILY_SKIP_ASSIGNMENT:
        selected.fault_target = sio_decoder_skip_assignment_target;
        selected.selected_target = mode == SIO_MODE_ATTACK ?
            sio_decoder_skip_assignment_target : sio_decoder_baseline_target;
        selected.selected_measure = mode == SIO_MODE_ATTACK ?
            sio_measure_decoder_skip_assignment : sio_measure_decoder_baseline;
        selected.assignment_executed = mode == SIO_MODE_ATTACK ? 0 : 1;
        selected.or_executed = 1;
        break;
    case SIO_FAMILY_SKIP_OR:
        selected.fault_target = sio_decoder_skip_or_target;
        selected.selected_target = mode == SIO_MODE_ATTACK ?
            sio_decoder_skip_or_target : sio_decoder_baseline_target;
        selected.selected_measure = mode == SIO_MODE_ATTACK ?
            sio_measure_decoder_skip_or : sio_measure_decoder_baseline;
        selected.assignment_executed = 1;
        selected.or_executed = mode == SIO_MODE_ATTACK ? 0 : 1;
        break;
    default:
        break;
    }
    return selected;
}

static void build_input(
    uint16_t share0[SIO_NWORDS],
    uint16_t share1[SIO_NWORDS],
    uint16_t initial[SIO_NWORDS],
    uint64_t domain,
    uint64_t sample) {
    uint64_t state = domain ^
        (sample * UINT64_C(0xd1342543de82ef95)) ^
        UINT64_C(0x53494f5f494e5055);
    unsigned int word;

    for (word = 0; word < SIO_NWORDS; ++word) {
        uint16_t plain = (uint16_t)splitmix64(&state);
        uint16_t mask_share = (uint16_t)splitmix64(&state);
        uint16_t stale = (uint16_t)splitmix64(&state);
        share0[word] = mask_share;
        share1[word] = (uint16_t)(mask_share ^ plain);
        initial[word] = stale;
    }

    {
        uint16_t target_mask = (uint16_t)SIO_TARGET_MASK;
        uint16_t plain =
            (uint16_t)(share0[SIO_TARGET_WORD] ^ share1[SIO_TARGET_WORD]);
        plain = (uint16_t)(plain | target_mask);
        share1[SIO_TARGET_WORD] =
            (uint16_t)(share0[SIO_TARGET_WORD] ^ plain);
        initial[SIO_TARGET_WORD] =
            (uint16_t)(initial[SIO_TARGET_WORD] & (uint16_t)~target_mask);
    }
}

static uint64_t tag_words(const uint16_t *words, size_t count) {
    uint64_t h = UINT64_C(1469598103934665603);
    size_t i;
    for (i = 0; i < count; ++i) {
        h ^= (uint8_t)words[i];
        h *= UINT64_C(1099511628211);
        h ^= (uint8_t)(words[i] >> 8);
        h *= UINT64_C(1099511628211);
    }
    return h;
}

static unsigned int changed_words(
    const uint16_t *left, const uint16_t *right) {
    unsigned int count = 0;
    unsigned int word;
    for (word = 0; word < SIO_NWORDS; ++word) {
        count += left[word] != right[word];
    }
    return count;
}

static unsigned int popcount16(uint16_t value) {
    unsigned int count = 0;
    while (value != 0u) {
        count += value & 1u;
        value = (uint16_t)(value >> 1);
    }
    return count;
}

static unsigned int changed_bits(
    const uint16_t *left, const uint16_t *right) {
    unsigned int count = 0;
    unsigned int word;
    for (word = 0; word < SIO_NWORDS; ++word) {
        count += popcount16((uint16_t)(left[word] ^ right[word]));
    }
    return count;
}

static unsigned int decoded_source_bit(
    const uint16_t *share0, const uint16_t *share1) {
    uint16_t plain =
        (uint16_t)(share0[SIO_TARGET_WORD] ^ share1[SIO_TARGET_WORD]);
    return (plain >> SIO_TARGET_BIT) & 1u;
}

static uint16_t word_before_target(
    const uint16_t *share0,
    const uint16_t *share1,
    const uint16_t *initial) {
    uint16_t word = initial[SIO_TARGET_WORD];
    uint16_t plain =
        (uint16_t)(share0[SIO_TARGET_WORD] ^ share1[SIO_TARGET_WORD]);
    unsigned int bitpos;
    for (bitpos = 0; bitpos < SIO_TARGET_BIT; ++bitpos) {
        unsigned int bit = (plain >> bitpos) & 1u;
        uint16_t mask = (uint16_t)(1u << bitpos);
        word = (uint16_t)(word & (uint16_t)~mask);
        word = (uint16_t)(word | (uint16_t)(bit << bitpos));
    }
    return word;
}

static const char *effective_mode_name(const sio_case *selected) {
    return selected->mode == SIO_MODE_ATTACK ?
        selected->family_label : "canonical-baseline";
}

static int semantic_case(
    uint64_t domain,
    uint64_t sample,
    const char *family_label,
    sio_mode mode) {
    uint16_t share0[SIO_NWORDS];
    uint16_t share1[SIO_NWORDS];
    uint16_t initial[SIO_NWORDS];
    uint16_t measured[SIO_NWORDS];
    uint16_t expected[SIO_NWORDS];
    uint16_t intended[SIO_NWORDS];
    sio_job job;
    sio_case selected = prepare_case(family_label, mode);

    if (selected.family == SIO_FAMILY_INVALID) {
        return 0;
    }
    build_input(share0, share1, initial, domain, sample);
    memset(measured, 0, sizeof(measured));
    memset(expected, 0, sizeof(expected));
    memset(intended, 0, sizeof(intended));
    job.share0 = share0;
    job.share1 = share1;
    job.initial = initial;

    job.output = measured;
    selected.selected_target(&job);
    job.output = expected;
    (mode == SIO_MODE_ATTACK ?
        selected.fault_target : selected.intended_target)(&job);
    job.output = intended;
    selected.intended_target(&job);

    if (memcmp(measured, expected, sizeof(measured)) != 0) {
        return 0;
    }
    if (mode == SIO_MODE_ATTACK) {
        if (memcmp(measured, intended, sizeof(measured)) == 0) {
            return 0;
        }
        if (changed_words(measured, intended) != 1u ||
            changed_bits(measured, intended) != 1u) {
            return 0;
        }
        if (((measured[SIO_TARGET_WORD] >> SIO_TARGET_BIT) & 1u) != 0u ||
            ((intended[SIO_TARGET_WORD] >> SIO_TARGET_BIT) & 1u) != 1u) {
            return 0;
        }
        return 1;
    }
    return memcmp(measured, intended, sizeof(measured)) == 0;
}

static void write_header(FILE *out) {
    unsigned int i;
    fputs(
        "sample,family,mode,is_attack,input_domain,"
        "semantic_valid,fault_applied,differs_intended,target_kind,"
        "target_word,target_bit,source_bit,stale_bit,expected_bit,used_bit,"
        "assignment_executed,or_executed,changed_words,changed_bits,"
        "intended_output_tag,output_tag,"
        "affinity_cpu,cpu_before,cpu_after,cpu_stable,"
        "sequence,time_enabled,time_running,running_percent,"
        "requested_mask,available_mask,open_error_mask,valid_mask,error_code",
        out);
    for (i = 0; i < SIO_HPC_EVENT_COUNT; ++i) {
        fprintf(out, ",%s", sio_event_name(i));
    }
    fputc('\n', out);
}

int main(int argc, char **argv) {
    const char *output_path = NULL;
    const char *family_label = NULL;
    unsigned long samples = 500u;
    unsigned long warmup = 20u;
    unsigned long domain = UINT64_C(0x53494f31);
    unsigned long counter_set = SIO_COUNTER_SET_STRUCTURAL_INSTRUCTIONS;
    unsigned long arg;
    int self_test = 0;
    int affinity_cpu = -1;
    sio_mode mode = SIO_MODE_UNSET;
    sio_case selected;
    FILE *out;
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
        } else if (strcmp(argv[arg], "--counter-set") == 0 &&
                   arg + 1 < (unsigned long)argc) {
            counter_set = parse_ulong(argv[++arg], "counter set");
        } else if (strcmp(argv[arg], "--cpu") == 0 &&
                   arg + 1 < (unsigned long)argc) {
            affinity_cpu = (int)parse_ulong(argv[++arg], "CPU");
        } else if (strcmp(argv[arg], "--output") == 0 &&
                   arg + 1 < (unsigned long)argc) {
            output_path = argv[++arg];
        } else if (strcmp(argv[arg], "--family-label") == 0 &&
                   arg + 1 < (unsigned long)argc) {
            family_label = argv[++arg];
        } else if (strcmp(argv[arg], "--mode") == 0 &&
                   arg + 1 < (unsigned long)argc) {
            const char *text = argv[++arg];
            if (strcmp(text, "baseline") == 0) {
                mode = SIO_MODE_BASELINE;
            } else if (strcmp(text, "attack") == 0) {
                mode = SIO_MODE_ATTACK;
            } else {
                fprintf(stderr, "[error] invalid mode: %s\n", text);
                return EXIT_FAILURE;
            }
        } else if (strcmp(argv[arg], "--self-test") == 0) {
            self_test = 1;
        } else {
            fprintf(stderr,
                    "usage: %s [--self-test] [--samples N] [--warmup N] "
                    "[--domain N] [--counter-set N] [--cpu N] "
                    "--family-label NAME --mode baseline|attack "
                    "[--output FILE]\n",
                    argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (family_label == NULL || mode == SIO_MODE_UNSET) {
        fprintf(stderr, "[error] --family-label and --mode are required\n");
        return EXIT_FAILURE;
    }
    selected = prepare_case(family_label, mode);
    if (selected.family == SIO_FAMILY_INVALID) {
        fprintf(stderr, "[error] invalid family label: %s\n", family_label);
        return EXIT_FAILURE;
    }
    if (sio_select_counter_set((unsigned int)counter_set) != 0) {
        fprintf(stderr, "[error] counter set must be in [1,%u]\n",
                SIO_COUNTER_SET_COUNT);
        return EXIT_FAILURE;
    }

    if (self_test) {
        for (i = 0; i < 1000u; ++i) {
            if (!semantic_case(
                    UINT64_C(0x53454d414e544943), i, family_label, mode)) {
                fprintf(stderr,
                        "[error] semantic self-test failed at %lu\n", i);
                return EXIT_FAILURE;
            }
        }
        printf(
            "semantic self-test passed: family=%s mode=%s "
            "attack=%d cases=1000\n",
            family_label,
            effective_mode_name(&selected),
            mode == SIO_MODE_ATTACK);
        return EXIT_SUCCESS;
    }

    if (output_path == NULL || samples == 0u || affinity_cpu < 0) {
        fprintf(stderr,
                "[error] --output, --cpu, and samples > 0 are required\n");
        return EXIT_FAILURE;
    }
    if (bind_to_cpu(affinity_cpu) != 0) {
        fprintf(stderr,
                "[error] unable to bind to CPU %d: %s\n",
                affinity_cpu,
                strerror(errno));
        return EXIT_FAILURE;
    }

    for (i = 0; i < warmup; ++i) {
        uint16_t share0[SIO_NWORDS];
        uint16_t share1[SIO_NWORDS];
        uint16_t initial[SIO_NWORDS];
        uint16_t result[SIO_NWORDS];
        sio_job job;
        build_input(
            share0, share1, initial,
            (uint64_t)domain ^ UINT64_C(0x53494f5f5741524d), i);
        job.share0 = share0;
        job.share1 = share1;
        job.initial = initial;
        job.output = result;
        selected.selected_target(&job);
    }

    {
        int rc = sio_hpc_init();
        if (rc != 0) {
            fprintf(
                stderr,
                "[error] perf_event_open initialization failed: %s (%d)\n",
                strerror(-rc),
                rc);
            fprintf(
                stderr,
                "[hint] check perf_event_paranoid, PMU access, "
                "and P-core affinity\n");
            return EXIT_FAILURE;
        }
    }

    out = fopen(output_path, "w");
    if (out == NULL) {
        perror("open output");
        sio_hpc_close();
        return EXIT_FAILURE;
    }
    write_header(out);

    for (i = 0; i < samples; ++i) {
        uint16_t share0[SIO_NWORDS];
        uint16_t share1[SIO_NWORDS];
        uint16_t initial[SIO_NWORDS];
        uint16_t measured[SIO_NWORDS];
        uint16_t expected[SIO_NWORDS];
        uint16_t intended[SIO_NWORDS];
        sio_job job;
        sio_hpc_snapshot snap;
        uint16_t before;
        unsigned int source;
        unsigned int stale;
        unsigned int expected_bit;
        unsigned int used_bit;
        unsigned int word_changes;
        unsigned int bit_changes;
        int cpu_before;
        int cpu_after;
        int cpu_stable;
        int semantic_valid;
        int differs_intended;
        int fault_applied;
        double running_percent;
        unsigned int event_index;

        build_input(share0, share1, initial, (uint64_t)domain, i);
        memset(measured, 0, sizeof(measured));
        memset(expected, 0, sizeof(expected));
        memset(intended, 0, sizeof(intended));
        job.share0 = share0;
        job.share1 = share1;
        job.initial = initial;
        job.output = measured;

        cpu_before = sched_getcpu();
        selected.selected_measure(&job);
        cpu_after = sched_getcpu();
        cpu_stable =
            cpu_before == affinity_cpu && cpu_after == affinity_cpu;
        sio_get_hpc_snapshot(&snap);

        job.output = expected;
        (mode == SIO_MODE_ATTACK ?
            selected.fault_target : selected.intended_target)(&job);
        job.output = intended;
        selected.intended_target(&job);

        semantic_valid =
            memcmp(measured, expected, sizeof(measured)) == 0;
        differs_intended =
            memcmp(measured, intended, sizeof(measured)) != 0;
        fault_applied =
            mode == SIO_MODE_ATTACK ?
                differs_intended : !differs_intended;
        word_changes = changed_words(measured, intended);
        bit_changes = changed_bits(measured, intended);
        before = word_before_target(share0, share1, initial);
        source = decoded_source_bit(share0, share1);
        stale = (before >> SIO_TARGET_BIT) & 1u;
        expected_bit =
            (intended[SIO_TARGET_WORD] >> SIO_TARGET_BIT) & 1u;
        used_bit =
            (measured[SIO_TARGET_WORD] >> SIO_TARGET_BIT) & 1u;
        running_percent =
            snap.time_enabled == 0u ?
                0.0 :
                100.0 * (double)snap.time_running /
                    (double)snap.time_enabled;

        fprintf(
            out,
            "%lu,%s,%s,%d,0x%016" PRIx64 ","
            "%d,%d,%d,bitsliced-masked-decoder,"
            "%u,%u,%u,%u,%u,%u,"
            "%d,%d,%u,%u,"
            "0x%016" PRIx64 ",0x%016" PRIx64 ","
            "%d,%d,%d,%d,"
            "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%.6f,"
            "0x%08" PRIx32 ",0x%08" PRIx32 ","
            "0x%08" PRIx32 ",0x%08" PRIx32 ",%" PRId32,
            i,
            family_label,
            effective_mode_name(&selected),
            mode == SIO_MODE_ATTACK,
            (uint64_t)domain,
            semantic_valid,
            fault_applied,
            differs_intended,
            SIO_TARGET_WORD,
            SIO_TARGET_BIT,
            source,
            stale,
            expected_bit,
            used_bit,
            selected.assignment_executed,
            selected.or_executed,
            word_changes,
            bit_changes,
            tag_words(intended, SIO_NWORDS),
            tag_words(measured, SIO_NWORDS),
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
        for (event_index = 0;
             event_index < SIO_HPC_EVENT_COUNT;
             ++event_index) {
            fprintf(out, ",%" PRIu64, snap.values[event_index]);
        }
        fputc('\n', out);

        if (!semantic_valid || !fault_applied ||
            (mode == SIO_MODE_ATTACK &&
             (word_changes != 1u || bit_changes != 1u ||
              source != 1u || stale != 0u ||
              expected_bit != 1u || used_bit != 0u))) {
            fprintf(
                stderr,
                "[error] semantic validation failed at sample %lu\n", i);
            fclose(out);
            sio_hpc_close();
            return EXIT_FAILURE;
        }
    }

    fclose(out);
    sio_hpc_close();
    return EXIT_SUCCESS;
}
