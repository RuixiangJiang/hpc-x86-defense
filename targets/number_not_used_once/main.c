#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "ravi_nnuo_x86.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static uint64_t checksum_vectors(const polyvecl *s1, const polyveck *s2)
{
    uint64_t value = UINT64_C(1469598103934665603);
    unsigned int v;
    unsigned int c;

    for (v = 0; v < (unsigned int)L; ++v) {
        for (c = 0; c < (unsigned int)N; ++c) {
            value ^= (uint32_t)s1->vec[v].coeffs[c];
            value *= UINT64_C(1099511628211);
        }
    }

    for (v = 0; v < (unsigned int)K; ++v) {
        for (c = 0; c < (unsigned int)N; ++c) {
            value ^= (uint32_t)s2->vec[v].coeffs[c];
            value *= UINT64_C(1099511628211);
        }
    }

    return value;
}

static int validate_audit(const nnuo_x86_audit_snapshot *audit)
{
    unsigned int target = audit->target_call;

    if (audit->valid == 0u || target >= NNUO_X86_TOTAL_CALLS) {
        return 0;
    }

#if NNUO_X86_BUILD_MODE == NNUO_X86_MODE_BASELINE
    if (audit->used_nonce_target != (uint16_t)target ||
        audit->nonce_progress_errors != 0u ||
        audit->duplicate_call != -1 ||
        audit->duplicate_output_equal != 0u) {
        return 0;
    }
#else
    {
        uint16_t expected_stale =
            target == 0u ? UINT16_MAX : (uint16_t)(target - 1u);
        uint32_t expected_errors =
            (uint32_t)(NNUO_X86_TOTAL_CALLS - target);

        if (audit->used_nonce_target != expected_stale ||
            audit->nonce_progress_errors != expected_errors) {
            return 0;
        }

        if (target == 0u) {
            if (audit->duplicate_call != -1) {
                return 0;
            }
        } else {
            if (audit->duplicate_call != (int32_t)(target - 1u) ||
                audit->duplicate_output_equal == 0u) {
                return 0;
            }
        }
    }
#endif

    return 1;
}

static void write_csv_header(FILE *out)
{
    unsigned int i;

    fputs("sample,mode,target_call,semantic_valid,used_nonce_target,"
          "expected_nonce_target,duplicate_call,nonce_progress_errors,"
          "duplicate_output_equal,checksum,sequence,sampling_invocations,"
          "time_enabled,time_running,running_percent,valid_mask,error_code",
          out);

    for (i = 0; i < NNUO_X86_EVENT_COUNT; ++i) {
        fprintf(out,
                ",%s",
                PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_event_name(i));
    }

    fputc('\n', out);
}

int main(int argc, char **argv)
{
    uint8_t seed[CRHBYTES];
    polyvecl s1;
    polyveck s2;
    const char *output_path = NULL;
    unsigned long samples = 500;
    unsigned long warmup = 20;
    unsigned long target_call = L;
    unsigned long i;
    nnuo_x86_audit_snapshot audit;
    int semantic_valid;
    FILE *out = NULL;
    int ret = EXIT_FAILURE;

    for (i = 1; i < (unsigned long)argc; ++i) {
        if (strcmp(argv[i], "--samples") == 0 &&
            i + 1u < (unsigned long)argc) {
            samples = parse_ulong(argv[++i], "samples");
        } else if (strcmp(argv[i], "--warmup") == 0 &&
                   i + 1u < (unsigned long)argc) {
            warmup = parse_ulong(argv[++i], "warmup");
        } else if (strcmp(argv[i], "--target-call") == 0 &&
                   i + 1u < (unsigned long)argc) {
            target_call = parse_ulong(argv[++i], "target call");
        } else if (strcmp(argv[i], "--output") == 0 &&
                   i + 1u < (unsigned long)argc) {
            output_path = argv[++i];
        } else {
            fprintf(stderr,
                    "usage: %s --output FILE [--samples N] [--warmup N] "
                    "[--target-call C]\n",
                    argv[0]);
            goto cleanup;
        }
    }

    if (output_path == NULL || samples == 0u) {
        fprintf(stderr,
                "[error] --output and samples greater than zero are required\n");
        goto cleanup;
    }

    if (target_call >= NNUO_X86_TOTAL_CALLS) {
        fprintf(stderr,
                "[error] target call must be in [0, %u)\n",
                NNUO_X86_TOTAL_CALLS);
        goto cleanup;
    }

    for (i = 0; i < (unsigned long)CRHBYTES; ++i) {
        seed[i] = (uint8_t)(0x4eu + 17u * (unsigned int)i);
    }

    PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_set_target(
        (unsigned int)target_call);

    /*
     * Semantic audit is completed with counters disabled. The additional
     * used-nonce recording and polynomial comparison never enter an HPC
     * sample.
     */
    memset(&s1, 0, sizeof(s1));
    memset(&s2, 0, sizeof(s2));
    PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_set_measurement_enabled(0);
    PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_set_audit_enabled(1);

    if (PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_sample_secret_vectors(
            &s1,
            &s2,
            seed) != 0) {
        fprintf(stderr, "[error] semantic audit execution failed\n");
        goto cleanup;
    }

    PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_get_audit_snapshot(&audit);
    semantic_valid = validate_audit(&audit);

    fprintf(stderr,
            "[audit] mode=%s target=%lu used=%u expected=%u "
            "duplicate=%" PRId32 " progression-errors=%" PRIu32 " "
            "duplicate-output-equal=%" PRIu32 " semantic-valid=%d\n",
            PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_mode_name(),
            target_call,
            (unsigned int)audit.used_nonce_target,
            (unsigned int)audit.expected_nonce_target,
            audit.duplicate_call,
            audit.nonce_progress_errors,
            audit.duplicate_output_equal,
            semantic_valid);

    if (!semantic_valid) {
        fprintf(stderr,
                "[error] fault semantics do not match the selected build mode\n");
        goto cleanup;
    }

    PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_set_audit_enabled(0);

    /*
     * Warmup uses the same implementation with measurement disabled.
     */
    for (i = 0; i < warmup; ++i) {
        memset(&s1, 0, sizeof(s1));
        memset(&s2, 0, sizeof(s2));

        if (PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_sample_secret_vectors(
                &s1,
                &s2,
                seed) != 0) {
            fprintf(stderr, "[error] warmup execution failed\n");
            goto cleanup;
        }
    }

    if (PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_hpc_init() != 0) {
        nnuo_x86_hpc_snapshot snapshot;
        PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_get_hpc_snapshot(&snapshot);
        fprintf(stderr,
                "[error] perf_event_open failed: %s (%" PRId32 ")\n",
                strerror(snapshot.error_code < 0 ?
                         -snapshot.error_code : snapshot.error_code),
                snapshot.error_code);
        goto cleanup;
    }

    out = fopen(output_path, "w");
    if (out == NULL) {
        fprintf(stderr,
                "[error] cannot open output file %s: %s\n",
                output_path,
                strerror(errno));
        goto cleanup;
    }

    write_csv_header(out);
    PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_set_measurement_enabled(1);

    for (i = 0; i < samples; ++i) {
        nnuo_x86_hpc_snapshot snapshot;
        uint64_t checksum;
        double running_percent;
        unsigned int event;

        memset(&s1, 0, sizeof(s1));
        memset(&s2, 0, sizeof(s2));

        if (PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_sample_secret_vectors(
                &s1,
                &s2,
                seed) != 0) {
            fprintf(stderr,
                    "[error] measured execution failed at sample %lu\n",
                    i);
            goto cleanup;
        }

        PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_get_hpc_snapshot(&snapshot);

        /*
         * The checksum is computed after counters are disabled. It keeps the
         * sampled outputs observable without contaminating the window.
         */
        checksum = checksum_vectors(&s1, &s2);

        running_percent = snapshot.time_enabled == 0u
                              ? 0.0
                              : 100.0 * (double)snapshot.time_running /
                                    (double)snapshot.time_enabled;

        fprintf(out,
                "%lu,%s,%lu,%d,%u,%u,%" PRId32 ",%" PRIu32 ","
                "%" PRIu32 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
                "%" PRIu64 ",%" PRIu64 ",%.6f,0x%08" PRIx32 ","
                "%" PRId32,
                i,
                PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_mode_name(),
                target_call,
                semantic_valid,
                (unsigned int)audit.used_nonce_target,
                (unsigned int)audit.expected_nonce_target,
                audit.duplicate_call,
                audit.nonce_progress_errors,
                audit.duplicate_output_equal,
                checksum,
                snapshot.sequence,
                snapshot.sampling_invocations,
                snapshot.time_enabled,
                snapshot.time_running,
                running_percent,
                snapshot.valid_mask,
                snapshot.error_code);

        for (event = 0; event < NNUO_X86_EVENT_COUNT; ++event) {
            fprintf(out, ",%" PRIu64, snapshot.values[event]);
        }

        fputc('\n', out);
    }

    if (fflush(out) != 0) {
        fprintf(stderr, "[error] failed to flush output CSV\n");
        goto cleanup;
    }

    fprintf(stderr,
            "[done] mode=%s samples=%lu output=%s\n",
            PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_mode_name(),
            samples,
            output_path);

    ret = EXIT_SUCCESS;

cleanup:
    if (out != NULL) {
        fclose(out);
    }

    PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_set_measurement_enabled(0);
    PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_set_audit_enabled(0);
    PQCLEAN_DILITHIUM2_CLEAN_nnuo_x86_hpc_close();
    return ret;
}
