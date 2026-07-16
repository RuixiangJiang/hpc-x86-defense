#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "api.h"
#include "fiddling_twiddle_x86.h"
#include "params.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FIDDLE_KEY_MAGIC "FTWDL002"
#define FIDDLE_KEY_MAGIC_LEN 8u

typedef struct {
    char magic[FIDDLE_KEY_MAGIC_LEN];
    uint64_t pk_len;
    uint64_t sk_len;
} fiddle_key_header;

static unsigned long parse_ulong(
    const char *text,
    const char *name)
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

static int parse_family(const char *text)
{
    if (strcmp(text, "corrupt-twiddle-pointer") == 0) {
        return FIDDLE_FAMILY_POINTER;
    }
    if (strcmp(text, "corrupt-loaded-twiddle-value") == 0) {
        return FIDDLE_FAMILY_LOADED_VALUE;
    }
    fprintf(stderr, "[error] unknown family: %s\n", text);
    exit(EXIT_FAILURE);
}

static int parse_mode(const char *text)
{
    if (strcmp(text, "baseline") == 0) {
        return FIDDLE_MODE_BASELINE;
    }
    if (strcmp(text, "attack") == 0) {
        return FIDDLE_MODE_ATTACK;
    }
    fprintf(stderr, "[error] unknown mode: %s\n", text);
    exit(EXIT_FAILURE);
}

static int write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;

    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int read_all(int fd, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;

    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n == 0) {
            errno = EIO;
            return -1;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int save_key_file(
    const char *path,
    const uint8_t *pk,
    const uint8_t *sk)
{
    fiddle_key_header hdr;
    int fd;

    memcpy(hdr.magic, FIDDLE_KEY_MAGIC, FIDDLE_KEY_MAGIC_LEN);
    hdr.pk_len = PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES;
    hdr.sk_len = PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES;

    fd = open(
        path,
        O_WRONLY | O_CREAT | O_TRUNC,
        S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return -1;
    }

    if (write_all(fd, &hdr, sizeof(hdr)) != 0 ||
        write_all(
            fd,
            pk,
            PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES) != 0 ||
        write_all(
            fd,
            sk,
            PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }

    return close(fd);
}

static int load_key_file(
    const char *path,
    uint8_t *pk,
    uint8_t *sk)
{
    fiddle_key_header hdr;
    int fd;

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    if (read_all(fd, &hdr, sizeof(hdr)) != 0 ||
        memcmp(hdr.magic, FIDDLE_KEY_MAGIC, FIDDLE_KEY_MAGIC_LEN) != 0 ||
        hdr.pk_len !=
            PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES ||
        hdr.sk_len !=
            PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES ||
        read_all(
            fd,
            pk,
            PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES) != 0 ||
        read_all(
            fd,
            sk,
            PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES) != 0) {
        int saved = errno != 0 ? errno : EINVAL;
        close(fd);
        errno = saved;
        return -1;
    }

    return close(fd);
}

static void build_message(
    uint8_t message[64],
    uint32_t domain,
    uint64_t sample)
{
    static const uint8_t prefix[] =
        "Ravi et al. Fiddling the Twiddle Constants";
    size_t prefix_len = sizeof(prefix) - 1u;

    memset(message, 0, 64);
    if (prefix_len > 44u) {
        prefix_len = 44u;
    }
    memcpy(message, prefix, prefix_len);

    message[44] = (uint8_t)(domain >> 0);
    message[45] = (uint8_t)(domain >> 8);
    message[46] = (uint8_t)(domain >> 16);
    message[47] = (uint8_t)(domain >> 24);

    message[48] = (uint8_t)(sample >> 0);
    message[49] = (uint8_t)(sample >> 8);
    message[50] = (uint8_t)(sample >> 16);
    message[51] = (uint8_t)(sample >> 24);
    message[52] = (uint8_t)(sample >> 32);
    message[53] = (uint8_t)(sample >> 40);
    message[54] = (uint8_t)(sample >> 48);
    message[55] = (uint8_t)(sample >> 56);
}

static int semantic_oracle(
    int family,
    int mode,
    int sign_ret,
    int verify_ret,
    const fiddle_twiddle_audit_snapshot *audit)
{
    if (mode == FIDDLE_MODE_BASELINE) {
        return sign_ret == 0 &&
            verify_ret == 0 &&
            audit->semantic_valid == 1u &&
            audit->fault_applied == 0u;
    }

    if (family == FIDDLE_FAMILY_POINTER) {
        return sign_ret == 0 &&
            verify_ret != 0 &&
            audit->semantic_valid == 1u &&
            audit->fault_applied == 1u &&
            audit->pointer_corrupted == 1u &&
            audit->twiddle_load_skipped == 0u;
    }

    return sign_ret == 0 &&
        verify_ret != 0 &&
        audit->semantic_valid == 1u &&
        audit->fault_applied == 1u &&
        audit->pointer_corrupted == 0u &&
        audit->twiddle_load_skipped == 1u &&
        audit->used_twiddle == 0;
}

static int run_self_test(
    int family,
    int mode,
    unsigned int target_vec,
    unsigned int target_index,
    unsigned int pointer_offset)
{
    uint8_t *pk = NULL;
    uint8_t *sk = NULL;
    uint8_t *sig = NULL;
    uint8_t message[64];
    size_t siglen = 0;
    int sign_ret;
    int verify_ret;
    int ok;
    fiddle_twiddle_audit_snapshot audit;

    pk = malloc(PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES);
    sk = malloc(PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES);
    sig = malloc(PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES);
    if (pk == NULL || sk == NULL || sig == NULL) {
        perror("malloc");
        free(sig);
        free(sk);
        free(pk);
        return 1;
    }

    if (PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair(pk, sk) != 0) {
        fprintf(stderr, "[error] self-test keypair failed\n");
        free(sig);
        free(sk);
        free(pk);
        return 1;
    }

    PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_configure(
        (unsigned int)family,
        (unsigned int)mode,
        target_vec,
        target_index,
        pointer_offset);
    PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_set_measurement_enabled(0);

    build_message(message, UINT32_C(0x53454c46), 0);
    sign_ret =
        PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature(
            sig,
            &siglen,
            message,
            sizeof(message),
            sk);
    verify_ret =
        sign_ret == 0
            ? PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify(
                  sig,
                  siglen,
                  message,
                  sizeof(message),
                  pk)
            : -1;

    PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_get_audit_snapshot(
        &audit);

    ok = semantic_oracle(
        family,
        mode,
        sign_ret,
        verify_ret,
        &audit);

    if (ok) {
        printf(
            "semantic self-test passed family=%s mode=%s "
            "correct_index=%u used_index=%u correct=%" PRId32
            " used=%" PRId32 "\n",
            PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_family_name(),
            PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_mode_name(),
            audit.target_twiddle_index,
            audit.used_twiddle_index,
            audit.correct_twiddle,
            audit.used_twiddle);
    } else {
        fprintf(
            stderr,
            "[error] semantic self-test failed family=%s mode=%s "
            "sign=%d verify=%d semantic=%u fault=%u "
            "pointer=%u skip_load=%u mismatches=%u/%u "
            "correct_index=%u used_index=%u correct=%" PRId32
            " used=%" PRId32 "\n",
            PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_family_name(),
            PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_mode_name(),
            sign_ret,
            verify_ret,
            audit.semantic_valid,
            audit.fault_applied,
            audit.pointer_corrupted,
            audit.twiddle_load_skipped,
            audit.target_group_mismatches,
            audit.final_ntt_mismatches,
            audit.target_twiddle_index,
            audit.used_twiddle_index,
            audit.correct_twiddle,
            audit.used_twiddle);
    }

    free(sig);
    free(sk);
    free(pk);
    return ok ? 0 : 1;
}

static void write_csv_header(FILE *out)
{
    unsigned int i;

    fputs(
        "sample,family,mode,is_attack,message_domain,"
        "target_vec,target_twiddle_index,used_twiddle_index,"
        "pointer_offset,target_len,target_start,"
        "sign_ret,siglen,verify_ret,oracle_success,"
        "correct_twiddle,used_twiddle,"
        "pointer_corrupted,twiddle_load_skipped,"
        "loaded_value_corrupted,"
        "target_group_mismatches,final_ntt_mismatches,"
        "fault_requested,fault_applied,semantic_valid,"
        "affinity_cpu,cpu_before,cpu_after,cpu_stable,"
        "sequence,signing_invocations,"
        "time_enabled,time_running,running_percent,"
        "valid_mask,error_code",
        out);

    for (i = 0; i < FIDDLE_TWIDDLE_HPC_EVENT_COUNT; ++i) {
        fprintf(
            out,
            ",%s",
            PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_event_name(i));
    }
    fputc('\n', out);
}

int main(int argc, char **argv)
{
    uint8_t *pk = NULL;
    uint8_t *sk = NULL;
    uint8_t *sig = NULL;
    uint8_t message[64];

    const char *output_path = NULL;
    const char *key_path = NULL;
    unsigned long samples = 500;
    unsigned long warmup = 10;
    unsigned long target_vec = 0;
    unsigned long target_twiddle_index = 8;
    unsigned long pointer_offset = 64;
    unsigned long message_domain = 0;
    int family = FIDDLE_FAMILY_LOADED_VALUE;
    int mode = FIDDLE_MODE_BASELINE;
    int create_key = 0;
    int self_test = 0;
    int affinity_cpu = -1;

    FILE *out = NULL;
    unsigned long i;
    int hpc_ret;
    int ret = EXIT_FAILURE;

    for (i = 1; i < (unsigned long)argc; ++i) {
        if (strcmp(argv[i], "--samples") == 0 &&
            i + 1 < (unsigned long)argc) {
            samples = parse_ulong(argv[++i], "samples");
        } else if (strcmp(argv[i], "--warmup") == 0 &&
                   i + 1 < (unsigned long)argc) {
            warmup = parse_ulong(argv[++i], "warmup");
        } else if (strcmp(argv[i], "--target-vec") == 0 &&
                   i + 1 < (unsigned long)argc) {
            target_vec = parse_ulong(argv[++i], "target vector");
        } else if (strcmp(argv[i], "--target-index") == 0 &&
                   i + 1 < (unsigned long)argc) {
            target_twiddle_index =
                parse_ulong(argv[++i], "target twiddle index");
        } else if (strcmp(argv[i], "--pointer-offset") == 0 &&
                   i + 1 < (unsigned long)argc) {
            pointer_offset =
                parse_ulong(argv[++i], "pointer offset");
        } else if (strcmp(argv[i], "--message-domain") == 0 &&
                   i + 1 < (unsigned long)argc) {
            message_domain =
                parse_ulong(argv[++i], "message domain");
        } else if (strcmp(argv[i], "--family") == 0 &&
                   i + 1 < (unsigned long)argc) {
            family = parse_family(argv[++i]);
        } else if (strcmp(argv[i], "--mode") == 0 &&
                   i + 1 < (unsigned long)argc) {
            mode = parse_mode(argv[++i]);
        } else if (strcmp(argv[i], "--cpu") == 0 &&
                   i + 1 < (unsigned long)argc) {
            affinity_cpu = (int)parse_ulong(argv[++i], "cpu");
        } else if (strcmp(argv[i], "--output") == 0 &&
                   i + 1 < (unsigned long)argc) {
            output_path = argv[++i];
        } else if (strcmp(argv[i], "--key-file") == 0 &&
                   i + 1 < (unsigned long)argc) {
            key_path = argv[++i];
        } else if (strcmp(argv[i], "--create-key") == 0) {
            create_key = 1;
        } else if (strcmp(argv[i], "--self-test") == 0) {
            self_test = 1;
        } else {
            fprintf(
                stderr,
                "usage: %s --family FAMILY --mode baseline|attack "
                "[--self-test] [--output FILE --key-file FILE] "
                "[--create-key] [--samples N] [--warmup N] "
                "[--target-vec V] [--target-index K] "
                "[--pointer-offset N] [--message-domain D] "
                "[--cpu N]\n",
                argv[0]);
            goto cleanup;
        }
    }

    if (target_vec >= (unsigned long)L ||
        target_twiddle_index == 0 ||
        target_twiddle_index >= (unsigned long)N) {
        fprintf(
            stderr,
            "[error] target must satisfy vec in [0,%d), "
            "twiddle index in [1,%d)\n",
            L,
            N);
        goto cleanup;
    }

    if (self_test) {
        return run_self_test(
            family,
            mode,
            (unsigned int)target_vec,
            (unsigned int)target_twiddle_index,
            (unsigned int)pointer_offset);
    }

    if (output_path == NULL || key_path == NULL || samples == 0) {
        fprintf(
            stderr,
            "[error] --output, --key-file, and samples > 0 "
            "are required\n");
        goto cleanup;
    }

    pk = malloc(PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES);
    sk = malloc(PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES);
    sig = malloc(PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES);
    if (pk == NULL || sk == NULL || sig == NULL) {
        perror("malloc");
        goto cleanup;
    }

    if (create_key) {
        if (PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair(pk, sk) != 0) {
            fprintf(stderr, "[error] keypair generation failed\n");
            goto cleanup;
        }
        if (save_key_file(key_path, pk, sk) != 0) {
            perror("save key file");
            goto cleanup;
        }
    } else if (load_key_file(key_path, pk, sk) != 0) {
        perror("load key file");
        goto cleanup;
    }

    hpc_ret = PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_hpc_init();
    if (hpc_ret != 0) {
        fprintf(
            stderr,
            "[error] perf_event_open group failed: %d (%s)\n",
            hpc_ret,
            strerror(-hpc_ret));
        fprintf(
            stderr,
            "[hint] check perf_event_paranoid, raw-event access, "
            "and P-core selection\n");
        goto cleanup;
    }

    PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_configure(
        (unsigned int)family,
        (unsigned int)mode,
        (unsigned int)target_vec,
        (unsigned int)target_twiddle_index,
        (unsigned int)pointer_offset);

    PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_set_measurement_enabled(0);
    for (i = 0; i < warmup; ++i) {
        size_t siglen = 0;
        build_message(
            message,
            (uint32_t)(message_domain ^ UINT32_C(0xa5a5a5a5)),
            i);
        if (PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature(
                sig,
                &siglen,
                message,
                sizeof(message),
                sk) != 0) {
            fprintf(stderr, "[error] warmup signing failed\n");
            goto cleanup_hpc;
        }
    }

    out = fopen(output_path, "w");
    if (out == NULL) {
        perror("fopen output");
        goto cleanup_hpc;
    }
    write_csv_header(out);

    for (i = 0; i < samples; ++i) {
        size_t siglen = 0;
        int sign_ret;
        int verify_ret;
        int oracle_success;
        int cpu_stable;
        double running_percent = 0.0;
        fiddle_twiddle_hpc_snapshot hpc;
        fiddle_twiddle_audit_snapshot audit;
        unsigned int event;

        build_message(
            message,
            (uint32_t)message_domain,
            (uint64_t)i);

        PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_set_measurement_enabled(1);
        sign_ret =
            PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature(
                sig,
                &siglen,
                message,
                sizeof(message),
                sk);
        PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_set_measurement_enabled(0);

        PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_get_hpc_snapshot(
            &hpc);
        PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_get_audit_snapshot(
            &audit);

        verify_ret =
            sign_ret == 0
                ? PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify(
                      sig,
                      siglen,
                      message,
                      sizeof(message),
                      pk)
                : -1;

        oracle_success = semantic_oracle(
            family,
            mode,
            sign_ret,
            verify_ret,
            &audit);

        if (hpc.time_enabled != 0) {
            running_percent =
                100.0 *
                (double)hpc.time_running /
                (double)hpc.time_enabled;
        }

        cpu_stable =
            hpc.cpu_before >= 0 &&
            hpc.cpu_before == hpc.cpu_after &&
            (affinity_cpu < 0 || hpc.cpu_before == affinity_cpu);

        fprintf(
            out,
            "%lu,%s,%s,%d,%lu,"
            "%u,%u,%u,%u,%u,%u,"
            "%d,%zu,%d,%d,"
            "%" PRId32 ",%" PRId32 ","
            "%u,%u,%u,"
            "%u,%u,"
            "%u,%u,%u,"
            "%d,%d,%d,%d,"
            "%" PRIu64 ",%" PRIu64 ","
            "%" PRIu64 ",%" PRIu64 ",%.6f,"
            "0x%08" PRIx32 ",%" PRId32,
            i,
            PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_family_name(),
            PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_mode_name(),
            mode == FIDDLE_MODE_ATTACK,
            message_domain,
            audit.target_vec,
            audit.target_twiddle_index,
            audit.used_twiddle_index,
            audit.pointer_offset,
            audit.target_len,
            audit.target_start,
            sign_ret,
            siglen,
            verify_ret,
            oracle_success,
            audit.correct_twiddle,
            audit.used_twiddle,
            audit.pointer_corrupted,
            audit.twiddle_load_skipped,
            audit.loaded_value_corrupted,
            audit.target_group_mismatches,
            audit.final_ntt_mismatches,
            audit.fault_requested,
            audit.fault_applied,
            audit.semantic_valid,
            affinity_cpu,
            hpc.cpu_before,
            hpc.cpu_after,
            cpu_stable,
            hpc.sequence,
            hpc.signing_invocations,
            hpc.time_enabled,
            hpc.time_running,
            running_percent,
            hpc.valid_mask,
            hpc.error_code);

        for (event = 0;
             event < FIDDLE_TWIDDLE_HPC_EVENT_COUNT;
             ++event) {
            fprintf(out, ",%" PRIu64, hpc.values[event]);
        }
        fputc('\n', out);
    }

    if (fclose(out) != 0) {
        out = NULL;
        perror("fclose output");
        goto cleanup_hpc;
    }
    out = NULL;

    printf(
        "[done] family=%s mode=%s samples=%lu "
        "target=(%lu,%lu) pointer_offset=%lu output=%s\n",
        PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_family_name(),
        PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_mode_name(),
        samples,
        target_vec,
        target_twiddle_index,
        pointer_offset,
        output_path);
    ret = EXIT_SUCCESS;

cleanup_hpc:
    PQCLEAN_DILITHIUM2_CLEAN_fiddle_twiddle_hpc_close();
cleanup:
    if (out != NULL) {
        fclose(out);
    }
    free(sig);
    free(sk);
    free(pk);
    return ret;
}
