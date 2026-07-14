#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "api.h"
#include "fiddling_twiddle_x86.h"
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

#ifndef FIDDLE_TWIDDLE_BUILD_MODE
#define FIDDLE_TWIDDLE_BUILD_MODE 0
#endif

#define FIDDLE_KEY_MAGIC "FTWDL001"
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

static const char *build_mode_name(void)
{
#if FIDDLE_TWIDDLE_BUILD_MODE == 0
    return "baseline";
#else
    return "zero-twiddle";
#endif
}

static void write_csv_header(FILE *out)
{
    unsigned int i;

    fputs(
        "sample,mode,message_domain,"
        "target_vec,target_twiddle_index,target_len,target_start,"
        "sign_ret,siglen,verify_ret,oracle_success,"
        "correct_twiddle,used_twiddle,twiddle_load_skipped,"
        "target_group_mismatches,final_ntt_mismatches,"
        "fault_requested,fault_applied,semantic_valid,"
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
    unsigned long message_domain = 0;
    int create_key = 0;

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
        } else if (strcmp(argv[i], "--message-domain") == 0 &&
                   i + 1 < (unsigned long)argc) {
            message_domain =
                parse_ulong(argv[++i], "message domain");
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
                "[--target-vec V] [--target-index K] "
                "[--message-domain D]\n",
                argv[0]);
            goto cleanup;
        }
    }

    if (output_path == NULL || key_path == NULL || samples == 0) {
        fprintf(
            stderr,
            "[error] --output, --key-file, and samples > 0 "
            "are required\n");
        goto cleanup;
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
        (unsigned int)target_vec,
        (unsigned int)target_twiddle_index);

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

#if FIDDLE_TWIDDLE_BUILD_MODE == 0
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
            "%lu,%s,%lu,"
            "%u,%u,%u,%u,"
            "%d,%zu,%d,%d,"
            "%" PRId32 ",%" PRId32 ",%u,"
            "%u,%u,"
            "%u,%u,%u,"
            "%" PRIu64 ",%" PRIu64 ","
            "%" PRIu64 ",%" PRIu64 ",%.6f,"
            "0x%08" PRIx32 ",%" PRId32,
            i,
            build_mode_name(),
            message_domain,
            audit.target_vec,
            audit.target_twiddle_index,
            audit.target_len,
            audit.target_start,
            sign_ret,
            siglen,
            verify_ret,
            oracle_success,
            audit.correct_twiddle,
            audit.used_twiddle,
            audit.twiddle_load_skipped,
            audit.target_group_mismatches,
            audit.final_ntt_mismatches,
            audit.fault_requested,
            audit.fault_applied,
            audit.semantic_valid,
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
        "[done] mode=%s samples=%lu target=(%lu,%lu) output=%s\n",
        build_mode_name(),
        samples,
        target_vec,
        target_twiddle_index,
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
