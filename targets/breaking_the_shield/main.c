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

typedef enum {
    BTS_MODE_UNSET = 0,
    BTS_MODE_BASELINE = 1,
    BTS_MODE_ATTACK = 2,
} bts_mode;

typedef enum {
    BTS_FAMILY_INVALID = 0,
    BTS_FAMILY_SHAKE_ABORT,
    BTS_FAMILY_SHAKE_SKIP,
    BTS_FAMILY_POLYZ_ZERO,
    BTS_FAMILY_POLYZ_STALE,
} bts_family;

typedef struct {
    bts_family family;
    bts_mode mode;
    const char *family_label;
    const char *target_kind;
    bts_target_fn selected_target;
    bts_target_fn intended_target;
    bts_target_fn fault_target;
    bts_measure_fn selected_measure;
    int shake_full_blocks_used;
    int shake_skipped_block;
    int polyz_substitute_value;
} bts_case;

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

static void fill_bytes(uint8_t *out, size_t length, uint64_t seed) {
    size_t offset;
    uint64_t state = seed;
    for (offset = 0; offset < length; offset += 8u) {
        uint64_t value = splitmix64(&state);
        unsigned int j;
        for (j = 0; j < 8u && offset + j < length; ++j) {
            out[offset + j] = (uint8_t)(value >> (8u * j));
        }
    }
}

static bts_family parse_family(const char *label) {
    if (strcmp(label, "abort-shake256-absorb-loop") == 0) {
        return BTS_FAMILY_SHAKE_ABORT;
    }
    if (strcmp(label, "skip-one-shake256-absorb-block") == 0) {
        return BTS_FAMILY_SHAKE_SKIP;
    }
    if (strcmp(label, "polyz-unpack-zero-load") == 0) {
        return BTS_FAMILY_POLYZ_ZERO;
    }
    if (strcmp(label, "polyz-unpack-stale-load") == 0) {
        return BTS_FAMILY_POLYZ_STALE;
    }
    return BTS_FAMILY_INVALID;
}

/* All family/mode dispatch finishes before the PMU window begins. */
static bts_case prepare_case(const char *label, bts_mode mode) {
    bts_case selected;
    memset(&selected, 0, sizeof(selected));
    selected.family = parse_family(label);
    selected.mode = mode;
    selected.family_label = label;
    selected.shake_skipped_block = -1;
    selected.polyz_substitute_value = -1;

    switch (selected.family) {
    case BTS_FAMILY_SHAKE_ABORT:
        selected.target_kind = "shake256-absorb";
        selected.intended_target = bts_shake_baseline_target;
        selected.fault_target = bts_shake_abort_target;
        selected.selected_target = mode == BTS_MODE_ATTACK ?
            bts_shake_abort_target : bts_shake_baseline_target;
        selected.selected_measure = mode == BTS_MODE_ATTACK ?
            bts_measure_shake_abort : bts_measure_shake_baseline;
        selected.shake_full_blocks_used = mode == BTS_MODE_ATTACK ?
            (int)BTS_SHAKE_ABORT_AFTER_BLOCKS : (int)BTS_SHAKE_FULL_BLOCKS;
        break;
    case BTS_FAMILY_SHAKE_SKIP:
        selected.target_kind = "shake256-absorb";
        selected.intended_target = bts_shake_baseline_target;
        selected.fault_target = bts_shake_skip_block_target;
        selected.selected_target = mode == BTS_MODE_ATTACK ?
            bts_shake_skip_block_target : bts_shake_baseline_target;
        selected.selected_measure = mode == BTS_MODE_ATTACK ?
            bts_measure_shake_skip_block : bts_measure_shake_baseline;
        selected.shake_full_blocks_used = mode == BTS_MODE_ATTACK ?
            (int)BTS_SHAKE_FULL_BLOCKS - 1 : (int)BTS_SHAKE_FULL_BLOCKS;
        selected.shake_skipped_block = mode == BTS_MODE_ATTACK ?
            (int)BTS_SHAKE_SKIP_BLOCK : -1;
        break;
    case BTS_FAMILY_POLYZ_ZERO:
        selected.target_kind = "polyz-unpack";
        selected.intended_target = bts_polyz_baseline_target;
        selected.fault_target = bts_polyz_zero_load_target;
        selected.selected_target = mode == BTS_MODE_ATTACK ?
            bts_polyz_zero_load_target : bts_polyz_baseline_target;
        selected.selected_measure = mode == BTS_MODE_ATTACK ?
            bts_measure_polyz_zero_load : bts_measure_polyz_baseline;
        selected.polyz_substitute_value = mode == BTS_MODE_ATTACK ? 0 : -1;
        break;
    case BTS_FAMILY_POLYZ_STALE:
        selected.target_kind = "polyz-unpack";
        selected.intended_target = bts_polyz_baseline_target;
        selected.fault_target = bts_polyz_stale_load_target;
        selected.selected_target = mode == BTS_MODE_ATTACK ?
            bts_polyz_stale_load_target : bts_polyz_baseline_target;
        selected.selected_measure = mode == BTS_MODE_ATTACK ?
            bts_measure_polyz_stale_load : bts_measure_polyz_baseline;
        selected.polyz_substitute_value = mode == BTS_MODE_ATTACK ?
            (int)BTS_POLYZ_STALE_BYTE : -1;
        break;
    default:
        break;
    }
    return selected;
}

static void build_input(uint8_t input[BTS_SHAKE_INPUT_BYTES],
                        bts_family family,
                        uint64_t domain,
                        uint64_t sample) {
    uint64_t fixed_seed = domain ^ UINT64_C(0x4254535f46495845);
    uint64_t sample_seed = domain ^
        (sample * UINT64_C(0xd1342543de82ef95)) ^
        UINT64_C(0x4254535f53414d50);

    memset(input, 0, BTS_SHAKE_INPUT_BYTES);
    if (family == BTS_FAMILY_SHAKE_ABORT) {
        fill_bytes(input, BTS_SHAKE_INPUT_BYTES, fixed_seed);
        fill_bytes(input + BTS_SHAKE_ABORT_AFTER_BLOCKS * BTS_SHAKE256_RATE,
                   (BTS_SHAKE_FULL_BLOCKS - BTS_SHAKE_ABORT_AFTER_BLOCKS) *
                       BTS_SHAKE256_RATE,
                   sample_seed);
    } else if (family == BTS_FAMILY_SHAKE_SKIP) {
        fill_bytes(input, BTS_SHAKE_INPUT_BYTES, fixed_seed);
        fill_bytes(input + BTS_SHAKE_SKIP_BLOCK * BTS_SHAKE256_RATE,
                   BTS_SHAKE256_RATE,
                   sample_seed);
    } else {
        fill_bytes(input, BTS_POLYZ_PACKEDBYTES, sample_seed);
        if (input[BTS_POLYZ_TARGET_INPUT_BYTE] == 0u ||
            input[BTS_POLYZ_TARGET_INPUT_BYTE] == BTS_POLYZ_STALE_BYTE) {
            input[BTS_POLYZ_TARGET_INPUT_BYTE] = UINT8_C(0xa7);
        }
    }
}

static size_t result_bytes(bts_family family) {
    return family == BTS_FAMILY_SHAKE_ABORT || family == BTS_FAMILY_SHAKE_SKIP ?
        BTS_SHAKE_OUTPUT_BYTES : BTS_N * sizeof(int32_t);
}

static uint64_t tag_bytes(const void *data, size_t length) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint64_t h = UINT64_C(1469598103934665603);
    size_t i;
    for (i = 0; i < length; ++i) {
        h ^= bytes[i];
        h *= UINT64_C(1099511628211);
    }
    return h;
}

static unsigned int changed_units(bts_family family,
                                  const bts_result *left,
                                  const bts_result *right) {
    unsigned int count = 0;
    unsigned int i;
    if (family == BTS_FAMILY_SHAKE_ABORT || family == BTS_FAMILY_SHAKE_SKIP) {
        for (i = 0; i < BTS_SHAKE_OUTPUT_BYTES; ++i) {
            count += left->shake[i] != right->shake[i];
        }
    } else {
        for (i = 0; i < BTS_N; ++i) {
            count += left->coeffs[i] != right->coeffs[i];
        }
    }
    return count;
}

static const char *effective_mode_name(const bts_case *selected) {
    return selected->mode == BTS_MODE_ATTACK ?
        selected->family_label : "canonical-baseline";
}

static int semantic_case(uint64_t domain, uint64_t sample,
                         const char *family_label, bts_mode mode) {
    uint8_t input[BTS_SHAKE_INPUT_BYTES];
    bts_case selected = prepare_case(family_label, mode);
    bts_result measured;
    bts_result expected;
    bts_result intended;
    bts_job job;
    size_t length;

    if (selected.family == BTS_FAMILY_INVALID) {
        return 0;
    }
    build_input(input, selected.family, domain, sample);
    memset(&measured, 0, sizeof(measured));
    memset(&expected, 0, sizeof(expected));
    memset(&intended, 0, sizeof(intended));
    job.input = input;
    job.output = &measured;
    job.fault_register_value = selected.family == BTS_FAMILY_POLYZ_STALE ?
        (uint32_t)BTS_POLYZ_STALE_BYTE : UINT32_C(0);
    bts_preload_fault_register(job.fault_register_value);
    selected.selected_target(&job);
    job.output = &expected;
    bts_preload_fault_register(job.fault_register_value);
    (mode == BTS_MODE_ATTACK ? selected.fault_target : selected.intended_target)(&job);
    job.output = &intended;
    bts_preload_fault_register(job.fault_register_value);
    selected.intended_target(&job);
    length = result_bytes(selected.family);
    if (memcmp(&measured, &expected, length) != 0) {
        return 0;
    }
    return mode == BTS_MODE_ATTACK ?
        memcmp(&measured, &intended, length) != 0 :
        memcmp(&measured, &intended, length) == 0;
}

static void write_header(FILE *out) {
    unsigned int i;
    fputs(
        "sample,family,mode,is_attack,input_domain,"
        "semantic_valid,fault_applied,differs_intended,target_kind,"
        "shake_full_blocks_intended,shake_full_blocks_used,shake_skipped_block,"
        "polyz_target_coeff,polyz_target_input_byte,polyz_substitute_value,"
        "changed_units,intended_output_tag,output_tag,"
        "affinity_cpu,cpu_before,cpu_after,cpu_stable,"
        "sequence,time_enabled,time_running,running_percent,"
        "requested_mask,available_mask,open_error_mask,valid_mask,error_code",
        out);
    for (i = 0; i < BTS_HPC_EVENT_COUNT; ++i) {
        fprintf(out, ",%s", bts_event_name(i));
    }
    fputc('\n', out);
}

int main(int argc, char **argv) {
    const char *output_path = NULL;
    const char *family_label = NULL;
    unsigned long samples = 500u;
    unsigned long warmup = 20u;
    unsigned long domain = UINT64_C(0x42545331);
    unsigned long counter_set = BTS_COUNTER_SET_STRUCTURAL_INSTRUCTIONS;
    unsigned long arg;
    int self_test = 0;
    int affinity_cpu = -1;
    bts_mode mode = BTS_MODE_UNSET;
    bts_case selected;
    FILE *out;
    unsigned long i;

    for (arg = 1; arg < (unsigned long)argc; ++arg) {
        if (strcmp(argv[arg], "--samples") == 0 && arg + 1 < (unsigned long)argc) {
            samples = parse_ulong(argv[++arg], "samples");
        } else if (strcmp(argv[arg], "--warmup") == 0 && arg + 1 < (unsigned long)argc) {
            warmup = parse_ulong(argv[++arg], "warmup");
        } else if (strcmp(argv[arg], "--domain") == 0 && arg + 1 < (unsigned long)argc) {
            domain = parse_ulong(argv[++arg], "domain");
        } else if (strcmp(argv[arg], "--counter-set") == 0 && arg + 1 < (unsigned long)argc) {
            counter_set = parse_ulong(argv[++arg], "counter set");
        } else if (strcmp(argv[arg], "--cpu") == 0 && arg + 1 < (unsigned long)argc) {
            affinity_cpu = (int)parse_ulong(argv[++arg], "CPU");
        } else if (strcmp(argv[arg], "--output") == 0 && arg + 1 < (unsigned long)argc) {
            output_path = argv[++arg];
        } else if (strcmp(argv[arg], "--family-label") == 0 && arg + 1 < (unsigned long)argc) {
            family_label = argv[++arg];
        } else if (strcmp(argv[arg], "--mode") == 0 && arg + 1 < (unsigned long)argc) {
            const char *text = argv[++arg];
            if (strcmp(text, "baseline") == 0) {
                mode = BTS_MODE_BASELINE;
            } else if (strcmp(text, "attack") == 0) {
                mode = BTS_MODE_ATTACK;
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
                    "--family-label NAME --mode baseline|attack [--output FILE]\n",
                    argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (family_label == NULL || mode == BTS_MODE_UNSET) {
        fprintf(stderr, "[error] --family-label and --mode are required\n");
        return EXIT_FAILURE;
    }
    selected = prepare_case(family_label, mode);
    if (selected.family == BTS_FAMILY_INVALID) {
        fprintf(stderr, "[error] invalid family label: %s\n", family_label);
        return EXIT_FAILURE;
    }
    if (bts_select_counter_set((unsigned int)counter_set) != 0) {
        fprintf(stderr, "[error] counter set must be in [1,%u]\n", BTS_COUNTER_SET_COUNT);
        return EXIT_FAILURE;
    }

    if (self_test) {
        for (i = 0; i < 1000u; ++i) {
            if (!semantic_case(UINT64_C(0x53454d414e544943), i,
                               family_label, mode)) {
                fprintf(stderr, "[error] semantic self-test failed at %lu\n", i);
                return EXIT_FAILURE;
            }
        }
        printf("semantic self-test passed: family=%s mode=%s attack=%d cases=1000\n",
               family_label, effective_mode_name(&selected),
               mode == BTS_MODE_ATTACK);
        return EXIT_SUCCESS;
    }

    if (output_path == NULL || samples == 0u || affinity_cpu < 0) {
        fprintf(stderr, "[error] --output, --cpu, and samples > 0 are required\n");
        return EXIT_FAILURE;
    }
    if (bind_to_cpu(affinity_cpu) != 0) {
        fprintf(stderr, "[error] unable to bind to CPU %d: %s\n",
                affinity_cpu, strerror(errno));
        return EXIT_FAILURE;
    }

    for (i = 0; i < warmup; ++i) {
        uint8_t input[BTS_SHAKE_INPUT_BYTES];
        bts_result result;
        bts_job job;
        build_input(input, selected.family,
                    (uint64_t)domain ^ UINT64_C(0x4254535f5741524d), i);
        memset(&result, 0, sizeof(result));
        job.input = input;
        job.output = &result;
        job.fault_register_value = selected.family == BTS_FAMILY_POLYZ_STALE ?
            (uint32_t)BTS_POLYZ_STALE_BYTE : UINT32_C(0);
        bts_preload_fault_register(job.fault_register_value);
        selected.selected_target(&job);
    }

    {
        int rc = bts_hpc_init();
        if (rc != 0) {
            fprintf(stderr, "[error] perf_event_open initialization failed: %s (%d)\n",
                    strerror(-rc), rc);
            fprintf(stderr, "[hint] check perf_event_paranoid, PMU access, and P-core affinity\n");
            return EXIT_FAILURE;
        }
    }

    out = fopen(output_path, "w");
    if (out == NULL) {
        perror("open output");
        bts_hpc_close();
        return EXIT_FAILURE;
    }
    write_header(out);

    for (i = 0; i < samples; ++i) {
        uint8_t input[BTS_SHAKE_INPUT_BYTES];
        bts_result measured;
        bts_result expected;
        bts_result intended;
        bts_job job;
        bts_hpc_snapshot snap;
        size_t length;
        int cpu_before;
        int cpu_after;
        int cpu_stable;
        int semantic_valid;
        int differs_intended;
        int fault_applied;
        unsigned int changed;
        double running_percent;
        unsigned int event_index;

        build_input(input, selected.family, (uint64_t)domain, i);
        memset(&measured, 0, sizeof(measured));
        memset(&expected, 0, sizeof(expected));
        memset(&intended, 0, sizeof(intended));
        job.input = input;
        job.output = &measured;
        job.fault_register_value = selected.family == BTS_FAMILY_POLYZ_STALE ?
            (uint32_t)BTS_POLYZ_STALE_BYTE : UINT32_C(0);

        cpu_before = sched_getcpu();
        /* The selected wrapper call happens before PMU enable inside that wrapper. */
        selected.selected_measure(&job);
        cpu_after = sched_getcpu();
        cpu_stable = cpu_before == affinity_cpu && cpu_after == affinity_cpu;
        bts_get_hpc_snapshot(&snap);

        job.output = &expected;
        bts_preload_fault_register(job.fault_register_value);
        (mode == BTS_MODE_ATTACK ? selected.fault_target : selected.intended_target)(&job);
        job.output = &intended;
        bts_preload_fault_register(job.fault_register_value);
        selected.intended_target(&job);
        length = result_bytes(selected.family);
        semantic_valid = memcmp(&measured, &expected, length) == 0;
        differs_intended = memcmp(&measured, &intended, length) != 0;
        fault_applied = mode == BTS_MODE_ATTACK ? differs_intended : !differs_intended;
        changed = changed_units(selected.family, &measured, &intended);
        running_percent = snap.time_enabled == 0u ? 0.0 :
            100.0 * (double)snap.time_running / (double)snap.time_enabled;

        fprintf(out,
                "%lu,%s,%s,%d,0x%016" PRIx64 ",%d,%d,%d,%s,"
                "%u,%d,%d,%d,%d,%d,%u,0x%016" PRIx64 ",0x%016" PRIx64 ","
                "%d,%d,%d,%d,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%.6f,"
                "0x%08" PRIx32 ",0x%08" PRIx32 ",0x%08" PRIx32 ",0x%08" PRIx32 ",%" PRId32,
                i, family_label, effective_mode_name(&selected),
                mode == BTS_MODE_ATTACK, (uint64_t)domain,
                semantic_valid, fault_applied, differs_intended,
                selected.target_kind,
                BTS_SHAKE_FULL_BLOCKS, selected.shake_full_blocks_used,
                selected.shake_skipped_block,
                selected.family == BTS_FAMILY_POLYZ_ZERO || selected.family == BTS_FAMILY_POLYZ_STALE ?
                    (int)BTS_POLYZ_TARGET_COEFF : -1,
                selected.family == BTS_FAMILY_POLYZ_ZERO || selected.family == BTS_FAMILY_POLYZ_STALE ?
                    (int)BTS_POLYZ_TARGET_INPUT_BYTE : -1,
                selected.polyz_substitute_value, changed,
                tag_bytes(&intended, length), tag_bytes(&measured, length),
                affinity_cpu, cpu_before, cpu_after, cpu_stable,
                snap.sequence, snap.time_enabled, snap.time_running, running_percent,
                snap.requested_mask, snap.available_mask, snap.open_error_mask,
                snap.valid_mask, snap.error_code);
        for (event_index = 0; event_index < BTS_HPC_EVENT_COUNT; ++event_index) {
            fprintf(out, ",%" PRIu64, snap.values[event_index]);
        }
        fputc('\n', out);

        if (!semantic_valid || !fault_applied) {
            fprintf(stderr, "[error] semantic validation failed at sample %lu\n", i);
            fclose(out);
            bts_hpc_close();
            return EXIT_FAILURE;
        }
    }

    fclose(out);
    bts_hpc_close();
    return EXIT_SUCCESS;
}
