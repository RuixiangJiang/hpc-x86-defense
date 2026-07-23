#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "api.h"
#include "krahmer_correction_fault_x86.h"
#include "params.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef KRAHMER_VARIANT
#define KRAHMER_VARIANT KRAHMER_VARIANT_CORRECTION
#endif

#ifndef KRAHMER_ATTACK_BUILD
#define KRAHMER_ATTACK_BUILD 0
#endif

#define KEY_MAGIC "KRAHCF02"
#define KEY_MAGIC_LEN 8u

typedef struct {
    char magic[KEY_MAGIC_LEN];
    uint64_t pk_len;
    uint64_t sk_len;
} key_header;

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
    key_header hdr;
    int fd;

    memcpy(hdr.magic, KEY_MAGIC, KEY_MAGIC_LEN);
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
    key_header hdr;
    int fd;

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    if (read_all(fd, &hdr, sizeof(hdr)) != 0 ||
        memcmp(hdr.magic, KEY_MAGIC, KEY_MAGIC_LEN) != 0 ||
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

static void build_fixed_message(
    uint8_t message[64],
    uint32_t domain)
{
    static const uint8_t prefix[] =
        "Krahmer correction faults on randomized Dilithium";
    size_t prefix_len = sizeof(prefix) - 1u;

    memset(message, 0, 64);
    if (prefix_len > 56u) {
        prefix_len = 56u;
    }
    memcpy(message, prefix, prefix_len);

    message[56] = (uint8_t)(domain >> 0);
    message[57] = (uint8_t)(domain >> 8);
    message[58] = (uint8_t)(domain >> 16);
    message[59] = (uint8_t)(domain >> 24);
}

static const char *mode_name(void)
{
#if KRAHMER_VARIANT == KRAHMER_VARIANT_CORRECTION
#if KRAHMER_ATTACK_BUILD == 0
    return "correction-baseline";
#else
    return "skip-add";
#endif
#else
#if KRAHMER_ATTACK_BUILD == 0
    return "a-baseline";
#else
    return "a-load-zero";
#endif
#endif
}

static void write_csv_header(FILE *out)
{
    unsigned int i;

    fputs(
        "sample,mode,counter_set,message_domain,attempts,"
        "sign_ret,siglen,verify_ret,oracle_success,"
        "variant,attack_build,"
        "target_vec,target_coeff,target_row,target_col,target_a_coeff,"
        "correction_base,correction_term,"
        "correction_expected,correction_used,"
        "a_original,a_faulty,matrix_output_mismatches,"
        "fault_requested,fault_applied,semantic_valid,"
        "sequence,target_invocations,"
        "time_enabled,time_running,running_percent,"
        "valid_mask,error_code",
        out);

    for (i = 0;
         i < PQCLEAN_DILITHIUM2_CLEAN_krahmer_event_count();
         ++i) {
        fprintf(
            out,
            ",%s",
            PQCLEAN_DILITHIUM2_CLEAN_krahmer_event_name(i));
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
    unsigned long message_domain = 0;
    unsigned long target_vec = 0;
    unsigned long target_coeff = 17;
    unsigned long target_row = 0;
    unsigned long target_col = 0;
    unsigned long target_a_coeff = 17;
    int create_key = 0;

    FILE *out = NULL;
    unsigned long i;
    int hpc_ret;
    int ret = EXIT_FAILURE;
    uint64_t previous_invocations = 0;

    for (i = 1; i < (unsigned long)argc; ++i) {
        if (strcmp(argv[i], "--samples") == 0 &&
            i + 1 < (unsigned long)argc) {
            samples = parse_ulong(argv[++i], "samples");
        } else if (strcmp(argv[i], "--warmup") == 0 &&
                   i + 1 < (unsigned long)argc) {
            warmup = parse_ulong(argv[++i], "warmup");
        } else if (strcmp(argv[i], "--message-domain") == 0 &&
                   i + 1 < (unsigned long)argc) {
            message_domain =
                parse_ulong(argv[++i], "message domain");
        } else if (strcmp(argv[i], "--target-vec") == 0 &&
                   i + 1 < (unsigned long)argc) {
            target_vec = parse_ulong(argv[++i], "target vector");
        } else if (strcmp(argv[i], "--target-coeff") == 0 &&
                   i + 1 < (unsigned long)argc) {
            target_coeff =
                parse_ulong(argv[++i], "target coefficient");
        } else if (strcmp(argv[i], "--target-row") == 0 &&
                   i + 1 < (unsigned long)argc) {
            target_row = parse_ulong(argv[++i], "target row");
        } else if (strcmp(argv[i], "--target-col") == 0 &&
                   i + 1 < (unsigned long)argc) {
            target_col = parse_ulong(argv[++i], "target column");
        } else if (strcmp(argv[i], "--target-a-coeff") == 0 &&
                   i + 1 < (unsigned long)argc) {
            target_a_coeff =
                parse_ulong(argv[++i], "target A coefficient");
        } else if (strcmp(argv[i], "--output") == 0 &&
                   i + 1 < (unsigned long)argc) {
            output_path = argv[++i];
        } else if (strcmp(argv[i], "--key-file") == 0 &&
                   i + 1 < (unsigned long)argc) {
            key_path = argv[++i];
        } else if (strcmp(argv[i], "--create-key") == 0) {
            create_key = 1;
        } else {
            fprintf(
                stderr,
                "usage: %s --output FILE --key-file FILE "
                "[--create-key] [--samples N] [--warmup N] "
                "[--message-domain D] "
                "[--target-vec V] [--target-coeff C] "
                "[--target-row R] [--target-col C] "
                "[--target-a-coeff C]\n",
                argv[0]);
            goto cleanup;
        }
    }

    if (output_path == NULL || key_path == NULL || samples == 0) {
        fprintf(
            stderr,
            "[error] --output, --key-file, and samples > 0 required\n");
        goto cleanup;
    }

    if (target_vec >= (unsigned long)L ||
        target_coeff >= (unsigned long)N ||
        target_row >= (unsigned long)K ||
        target_col >= (unsigned long)L ||
        target_a_coeff >= (unsigned long)N) {
        fprintf(stderr, "[error] target configuration out of range\n");
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

    hpc_ret = PQCLEAN_DILITHIUM2_CLEAN_krahmer_hpc_init();
    if (hpc_ret != 0) {
        fprintf(
            stderr,
            "[error] perf_event_open group failed: %d (%s)\n",
            hpc_ret,
            strerror(-hpc_ret));
        fprintf(
            stderr,
            "[hint] check perf_event_paranoid, event support, "
            "raw load/store event codes, and P-core selection\n");
        goto cleanup;
    }

    PQCLEAN_DILITHIUM2_CLEAN_krahmer_configure(
        (unsigned int)target_vec,
        (unsigned int)target_coeff,
        (unsigned int)target_row,
        (unsigned int)target_col,
        (unsigned int)target_a_coeff);

    build_fixed_message(message, (uint32_t)message_domain);

    PQCLEAN_DILITHIUM2_CLEAN_krahmer_set_measurement_enabled(0);
    for (i = 0; i < warmup; ++i) {
        size_t siglen = 0;
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

    {
        krahmer_hpc_snapshot initial;
        PQCLEAN_DILITHIUM2_CLEAN_krahmer_get_hpc_snapshot(&initial);
        previous_invocations = initial.target_invocations;
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
        uint64_t attempts;
        double running_percent = 0.0;
        krahmer_hpc_snapshot hpc;
        krahmer_audit_snapshot audit;
        unsigned int event;

        PQCLEAN_DILITHIUM2_CLEAN_krahmer_set_measurement_enabled(1);
        sign_ret =
            PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature(
                sig,
                &siglen,
                message,
                sizeof(message),
                sk);
        PQCLEAN_DILITHIUM2_CLEAN_krahmer_set_measurement_enabled(0);

        PQCLEAN_DILITHIUM2_CLEAN_krahmer_get_hpc_snapshot(&hpc);
        PQCLEAN_DILITHIUM2_CLEAN_krahmer_get_audit_snapshot(&audit);

        attempts = hpc.target_invocations - previous_invocations;
        previous_invocations = hpc.target_invocations;

        verify_ret =
            sign_ret == 0
                ? PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify(
                      sig,
                      siglen,
                      message,
                      sizeof(message),
                      pk)
                : -1;

#if KRAHMER_ATTACK_BUILD == 0
        oracle_success =
            sign_ret == 0 &&
            verify_ret == 0 &&
            audit.semantic_valid == 1u;
#else
        oracle_success =
            sign_ret == 0 &&
            verify_ret != 0 &&
            audit.semantic_valid == 1u;
#endif

        if (hpc.time_enabled != 0) {
            running_percent =
                100.0 *
                (double)hpc.time_running /
                (double)hpc.time_enabled;
        }

        fprintf(
            out,
            "%lu,%s,%s,0x%08lx,%" PRIu64 ","
            "%d,%zu,%d,%d,"
            "%u,%u,"
            "%u,%u,%u,%u,%u,"
            "%" PRId32 ",%" PRId32 ","
            "%" PRId32 ",%" PRId32 ","
            "%" PRId32 ",%" PRId32 ",%u,"
            "%u,%u,%u,"
            "%" PRIu64 ",%" PRIu64 ","
            "%" PRIu64 ",%" PRIu64 ",%.6f,"
            "0x%08" PRIx32 ",%" PRId32,
            i,
            mode_name(),
            PQCLEAN_DILITHIUM2_CLEAN_krahmer_counter_set_name(),
            message_domain,
            attempts,
            sign_ret,
            siglen,
            verify_ret,
            oracle_success,
            audit.variant,
            audit.attack_build,
            audit.target_vec,
            audit.target_coeff,
            audit.target_row,
            audit.target_col,
            audit.target_a_coeff,
            audit.correction_base,
            audit.correction_term,
            audit.correction_expected,
            audit.correction_used,
            audit.a_original,
            audit.a_faulty,
            audit.matrix_output_mismatches,
            audit.fault_requested,
            audit.fault_applied,
            audit.semantic_valid,
            hpc.sequence,
            hpc.target_invocations,
            hpc.time_enabled,
            hpc.time_running,
            running_percent,
            hpc.valid_mask,
            hpc.error_code);

        for (event = 0;
             event < PQCLEAN_DILITHIUM2_CLEAN_krahmer_event_count();
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
        "[done] mode=%s counter_set=%s samples=%lu output=%s\n",
        mode_name(),
        PQCLEAN_DILITHIUM2_CLEAN_krahmer_counter_set_name(),
        samples,
        output_path);
    ret = EXIT_SUCCESS;

cleanup_hpc:
    PQCLEAN_DILITHIUM2_CLEAN_krahmer_hpc_close();
cleanup:
    if (out != NULL) {
        fclose(out);
    }
    free(sig);
    free(sk);
    free(pk);
    return ret;
}
