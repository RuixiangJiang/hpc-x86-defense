#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "when_randomness_isnt_random_x86.h"

#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WRIR_INTENDED_DOMAIN
#define WRIR_INTENDED_DOMAIN 4
#endif

#ifndef WRIR_WRONG_DOMAIN
#define WRIR_WRONG_DOMAIN 0
#endif

#ifndef WRIR_REDIRECT_BYTE
#define WRIR_REDIRECT_BYTE 0xa5
#endif

#define WRIR_SEED_OFFSET WRIR_SEEDBYTES
#define WRIR_SEED_MATERIAL_BYTES (WRIR_SEED_OFFSET + WRIR_CRHBYTES)

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

static void build_seed_material(uint8_t material[WRIR_SEED_MATERIAL_BYTES],
                                uint64_t domain,
                                uint64_t sample) {
    uint64_t state = domain ^
        (sample * UINT64_C(0xd1342543de82ef95)) ^
        UINT64_C(0x575249525f534545);
    unsigned int i;
    for (i = 0; i < WRIR_SEED_MATERIAL_BYTES; i += 8u) {
        uint64_t value = splitmix64(&state);
        unsigned int j;
        for (j = 0; j < 8u && i + j < WRIR_SEED_MATERIAL_BYTES; ++j) {
            material[i + j] = (uint8_t)(value >> (8u * j));
        }
    }
}

static void build_redirect_seed(uint8_t seed[WRIR_CRHBYTES]) {
    unsigned int i;
    for (i = 0; i < WRIR_CRHBYTES; ++i) {
        seed[i] = (uint8_t)(WRIR_REDIRECT_BYTE ^ (uint8_t)(13u * i));
    }
}

static uint64_t tag_bytes(const uint8_t *data, size_t length) {
    uint64_t h = UINT64_C(1469598103934665603);
    size_t i;
    for (i = 0; i < length; ++i) {
        h ^= data[i];
        h *= UINT64_C(1099511628211);
    }
    return h;
}

static uint64_t tag_poly(const wrir_poly *poly) {
    uint64_t h = UINT64_C(1469598103934665603);
    unsigned int i;
    for (i = 0; i < WRIR_N; ++i) {
        uint32_t x = (uint32_t)poly->coeffs[i];
        unsigned int j;
        for (j = 0; j < 4u; ++j) {
            h ^= (uint8_t)(x >> (8u * j));
            h *= UINT64_C(1099511628211);
        }
    }
    return h;
}

typedef struct {
    const uint8_t *intended_seed;
    const uint8_t *used_seed;
    uint16_t intended_nonce;
    uint16_t used_nonce;
    int intended_offset;
    int used_offset;
    int redirected;
} wrir_arguments;

typedef enum {
    WRIR_MODE_UNSET = 0,
    WRIR_MODE_BASELINE = 1,
    WRIR_MODE_ATTACK = 2,
} wrir_mode;

static int valid_family_label(const char *label) {
    return strcmp(label, "skip-seed-pointer-offset") == 0 ||
           strcmp(label, "wrong-domain-index") == 0 ||
           strcmp(label, "redirect-seed-pointer") == 0;
}

static const char *effective_mode_name(wrir_mode mode,
                                       const char *family_label) {
    return mode == WRIR_MODE_ATTACK ? family_label : "canonical-baseline";
}

static wrir_arguments prepare_arguments(
    const uint8_t material[WRIR_SEED_MATERIAL_BYTES],
    const uint8_t redirect_seed[WRIR_CRHBYTES],
    const char *family_label,
    wrir_mode mode) {
    wrir_arguments args;
    args.intended_seed = material + WRIR_SEED_OFFSET;
    args.used_seed = args.intended_seed;
    args.intended_nonce = 0u;
    args.used_nonce = 0u;
    args.intended_offset = (int)WRIR_SEED_OFFSET;
    args.used_offset = (int)WRIR_SEED_OFFSET;
    args.redirected = 0;

    if (strcmp(family_label, "wrong-domain-index") == 0) {
        args.intended_nonce = (uint16_t)WRIR_INTENDED_DOMAIN;
        args.used_nonce = (uint16_t)WRIR_INTENDED_DOMAIN;
    }

    /* This runtime dispatch is complete before wrir_hpc_begin(). */
    if (mode == WRIR_MODE_ATTACK) {
        if (strcmp(family_label, "skip-seed-pointer-offset") == 0) {
            args.used_seed = material;
            args.used_offset = 0;
        } else if (strcmp(family_label, "wrong-domain-index") == 0) {
            args.used_nonce = (uint16_t)WRIR_WRONG_DOMAIN;
        } else {
            args.used_seed = redirect_seed;
            args.used_offset = -1;
            args.redirected = 1;
        }
    }
    return args;
}

static int semantic_case(uint64_t domain, uint64_t sample,
                         const char *family_label, wrir_mode mode) {
    uint8_t material[WRIR_SEED_MATERIAL_BYTES];
    uint8_t redirect_seed[WRIR_CRHBYTES];
    wrir_arguments args;
    wrir_poly measured;
    wrir_poly fault_oracle;
    wrir_poly intended_oracle;
    int differs_intended;

    build_seed_material(material, domain, sample);
    build_redirect_seed(redirect_seed);
    args = prepare_arguments(material, redirect_seed, family_label, mode);

    wrir_sampler_target(&measured, args.used_seed, args.used_nonce);
    wrir_reference_sampler(&fault_oracle, args.used_seed, args.used_nonce);
    wrir_reference_sampler(&intended_oracle,
                           args.intended_seed,
                           args.intended_nonce);
    differs_intended = memcmp(&measured, &intended_oracle, sizeof(measured)) != 0;

    if (memcmp(&measured, &fault_oracle, sizeof(measured)) != 0) {
        return 0;
    }
    if (mode == WRIR_MODE_ATTACK) {
        return differs_intended;
    }
    return !differs_intended;
}

static void write_header(FILE *out) {
    unsigned int i;
    fputs(
        "sample,family,mode,is_attack,input_domain,"
        "intended_seed_offset,used_seed_offset,seed_redirected,"
        "intended_domain_index,used_domain_index,"
        "semantic_valid,fault_applied,differs_intended,"
        "intended_seed_tag,used_seed_tag,intended_output_tag,output_tag,"
        "affinity_cpu,cpu_before,cpu_after,cpu_stable,"
        "sequence,time_enabled,time_running,running_percent,"
        "requested_mask,available_mask,open_error_mask,valid_mask,error_code",
        out);
    for (i = 0; i < WRIR_HPC_EVENT_COUNT; ++i) {
        fprintf(out, ",%s", wrir_event_name(i));
    }
    fputc('\n', out);
}

int main(int argc, char **argv) {
    const char *output_path = NULL;
    unsigned long samples = 500u;
    unsigned long warmup = 20u;
    unsigned long domain = UINT64_C(0x57524952);
    unsigned long counter_set = WRIR_COUNTER_SET_STRUCTURAL_INSTRUCTIONS;
    unsigned long arg;
    int self_test = 0;
    int affinity_cpu = -1;
    const char *family_label = NULL;
    wrir_mode mode = WRIR_MODE_UNSET;
    FILE *out = NULL;
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
            if (!valid_family_label(family_label)) {
                fprintf(stderr, "[error] invalid family label: %s\n", family_label);
                return EXIT_FAILURE;
            }
        } else if (strcmp(argv[arg], "--mode") == 0 && arg + 1 < (unsigned long)argc) {
            const char *text = argv[++arg];
            if (strcmp(text, "baseline") == 0) {
                mode = WRIR_MODE_BASELINE;
            } else if (strcmp(text, "attack") == 0) {
                mode = WRIR_MODE_ATTACK;
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

    if (family_label == NULL || mode == WRIR_MODE_UNSET) {
        fprintf(stderr, "[error] --family-label and --mode are required\n");
        return EXIT_FAILURE;
    }
    if (wrir_select_counter_set((unsigned int)counter_set) != 0) {
        fprintf(stderr, "[error] counter set must be in [1,%u]\n",
                WRIR_COUNTER_SET_COUNT);
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
               family_label, effective_mode_name(mode, family_label),
               mode == WRIR_MODE_ATTACK);
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
        uint8_t material[WRIR_SEED_MATERIAL_BYTES];
        uint8_t redirect_seed[WRIR_CRHBYTES];
        wrir_arguments args;
        wrir_poly poly;
        build_seed_material(material, domain ^ UINT64_C(0x57524d55), i);
        build_redirect_seed(redirect_seed);
        args = prepare_arguments(material, redirect_seed, family_label, mode);
        wrir_sampler_target(&poly, args.used_seed, args.used_nonce);
    }

    {
        int rc = wrir_hpc_init();
        if (rc != 0) {
            fprintf(stderr, "[error] perf_event_open initialization failed: %s (%d)\n",
                    strerror(-rc), rc);
            fprintf(stderr, "[hint] check perf_event_paranoid, PMU event access, and P-core affinity\n");
            return EXIT_FAILURE;
        }
    }

    out = fopen(output_path, "w");
    if (out == NULL) {
        perror("open output");
        wrir_hpc_close();
        return EXIT_FAILURE;
    }
    write_header(out);

    for (i = 0; i < samples; ++i) {
        uint8_t material[WRIR_SEED_MATERIAL_BYTES];
        uint8_t redirect_seed[WRIR_CRHBYTES];
        wrir_arguments args;
        wrir_poly measured;
        wrir_poly fault_oracle;
        wrir_poly intended_oracle;
        wrir_hpc_snapshot snap;
        int cpu_before;
        int cpu_after;
        int cpu_stable;
        int semantic_valid;
        int fault_applied;
        int differs_intended;
        double running_percent;
        unsigned int event_index;

        build_seed_material(material, (uint64_t)domain, i);
        build_redirect_seed(redirect_seed);
        args = prepare_arguments(material, redirect_seed, family_label, mode);

        cpu_before = sched_getcpu();
        wrir_measure_target(&measured, args.used_seed, args.used_nonce);
        cpu_after = sched_getcpu();
        cpu_stable = cpu_before == affinity_cpu && cpu_after == affinity_cpu;
        wrir_get_hpc_snapshot(&snap);

        wrir_reference_sampler(&fault_oracle, args.used_seed, args.used_nonce);
        wrir_reference_sampler(&intended_oracle,
                               args.intended_seed,
                               args.intended_nonce);
        semantic_valid = memcmp(&measured, &fault_oracle, sizeof(measured)) == 0;
        differs_intended = memcmp(&measured, &intended_oracle, sizeof(measured)) != 0;
        fault_applied = mode == WRIR_MODE_ATTACK ?
            differs_intended : !differs_intended;

        running_percent = snap.time_enabled == 0u ? 0.0 :
            100.0 * (double)snap.time_running / (double)snap.time_enabled;

        fprintf(out,
                "%lu,%s,%s,%d,0x%016" PRIx64 ",%d,%d,%d,%u,%u,%d,%d,%d,"
                "0x%016" PRIx64 ",0x%016" PRIx64 ",0x%016" PRIx64 ",0x%016" PRIx64 ","
                "%d,%d,%d,%d,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%.6f,"
                "0x%08" PRIx32 ",0x%08" PRIx32 ",0x%08" PRIx32 ",0x%08" PRIx32 ",%" PRId32,
                i, family_label, effective_mode_name(mode, family_label),
                mode == WRIR_MODE_ATTACK,
                (uint64_t)domain,
                args.intended_offset, args.used_offset, args.redirected,
                (unsigned int)args.intended_nonce, (unsigned int)args.used_nonce,
                semantic_valid, fault_applied, differs_intended,
                tag_bytes(args.intended_seed, WRIR_CRHBYTES),
                tag_bytes(args.used_seed, WRIR_CRHBYTES),
                tag_poly(&intended_oracle), tag_poly(&measured),
                affinity_cpu, cpu_before, cpu_after, cpu_stable,
                snap.sequence, snap.time_enabled, snap.time_running, running_percent,
                snap.requested_mask, snap.available_mask, snap.open_error_mask,
                snap.valid_mask, snap.error_code);
        for (event_index = 0; event_index < WRIR_HPC_EVENT_COUNT; ++event_index) {
            fprintf(out, ",%" PRIu64, snap.values[event_index]);
        }
        fputc('\n', out);

        if (!semantic_valid || !fault_applied) {
            fprintf(stderr, "[error] semantic validation failed at sample %lu\n", i);
            fclose(out);
            wrir_hpc_close();
            return EXIT_FAILURE;
        }
    }

    fclose(out);
    wrir_hpc_close();
    return EXIT_SUCCESS;
}
