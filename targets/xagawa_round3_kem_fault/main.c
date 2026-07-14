#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "api.h"
#include "params.h"
#include "xagawa_failure_handling_x86.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define KEY_MAGIC "XAGAWK01"
#define KEY_MAGIC_LEN 8u

typedef struct {
    char magic[KEY_MAGIC_LEN];
    uint64_t pk_len;
    uint64_t sk_len;
} key_header;

static unsigned long parse_ulong(const char *text,
                                 const char *name)
{
    char *end = NULL;
    unsigned long value;

    errno = 0;
    value = strtoul(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0') {
        fprintf(stderr,
                "[error] invalid %s: %s\n",
                name,
                text);
        exit(EXIT_FAILURE);
    }
    return value;
}

static int write_all(int fd,
                     const void *buf,
                     size_t len)
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

static int read_all(int fd,
                    void *buf,
                    size_t len)
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

static int save_key_file(const char *path,
                         const uint8_t *pk,
                         const uint8_t *sk)
{
    key_header hdr;
    int fd;

    memcpy(hdr.magic, KEY_MAGIC, KEY_MAGIC_LEN);
    hdr.pk_len =
        PQCLEAN_KYBER512_CLEAN_CRYPTO_PUBLICKEYBYTES;
    hdr.sk_len =
        PQCLEAN_KYBER512_CLEAN_CRYPTO_SECRETKEYBYTES;

    fd = open(path,
              O_WRONLY | O_CREAT | O_TRUNC,
              S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return -1;
    }

    if (write_all(fd, &hdr, sizeof(hdr)) != 0 ||
        write_all(
            fd,
            pk,
            PQCLEAN_KYBER512_CLEAN_CRYPTO_PUBLICKEYBYTES) != 0 ||
        write_all(
            fd,
            sk,
            PQCLEAN_KYBER512_CLEAN_CRYPTO_SECRETKEYBYTES) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }

    return close(fd);
}

static int load_key_file(const char *path,
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
            PQCLEAN_KYBER512_CLEAN_CRYPTO_PUBLICKEYBYTES ||
        hdr.sk_len !=
            PQCLEAN_KYBER512_CLEAN_CRYPTO_SECRETKEYBYTES ||
        read_all(
            fd,
            pk,
            PQCLEAN_KYBER512_CLEAN_CRYPTO_PUBLICKEYBYTES) != 0 ||
        read_all(
            fd,
            sk,
            PQCLEAN_KYBER512_CLEAN_CRYPTO_SECRETKEYBYTES) != 0) {
        int saved = errno != 0 ? errno : EINVAL;
        close(fd);
        errno = saved;
        return -1;
    }

    return close(fd);
}

static void tamper_ciphertext(uint8_t *ct,
                              unsigned long byte_index,
                              unsigned long mask)
{
    ct[byte_index] ^= (uint8_t)mask;
}

static void write_csv_header(FILE *out)
{
    unsigned int i;

    fputs("sample,mode,tamper_byte,tamper_mask,"
          "enc_ret,dec_ret,ss_matches_encapsulated,"
          "fault_oracle,semantic_valid,"
          "fail_flag,cmov_len,prekey_preserved,"
          "fallback_applied,"
          "sequence,failure_handling_invocations,"
          "time_enabled,time_running,running_percent,"
          "valid_mask,error_code",
          out);

    for (i = 0;
         i < XAGAWA_FAILURE_HPC_EVENT_COUNT;
         ++i) {
        fprintf(
            out,
            ",%s",
            PQCLEAN_KYBER512_CLEAN_xagawa_failure_event_name(i));
    }
    fputc('\n', out);
}

int main(int argc, char **argv)
{
    uint8_t *pk = NULL;
    uint8_t *sk = NULL;
    uint8_t *ct = NULL;
    uint8_t ss_enc[
        PQCLEAN_KYBER512_CLEAN_CRYPTO_BYTES];
    uint8_t ss_dec[
        PQCLEAN_KYBER512_CLEAN_CRYPTO_BYTES];
    const char *output_path = NULL;
    const char *key_path = NULL;
    unsigned long samples = 500;
    unsigned long warmup = 10;
    unsigned long tamper_byte = 0;
    unsigned long tamper_mask = 1;
    int create_key = 0;
    FILE *out = NULL;
    unsigned long i;
    int ret = EXIT_FAILURE;

    for (i = 1; i < (unsigned long)argc; ++i) {
        if (strcmp(argv[i], "--samples") == 0 &&
            i + 1 < (unsigned long)argc) {
            samples = parse_ulong(argv[++i], "samples");
        } else if (strcmp(argv[i], "--warmup") == 0 &&
                   i + 1 < (unsigned long)argc) {
            warmup = parse_ulong(argv[++i], "warmup");
        } else if (strcmp(argv[i], "--tamper-byte") == 0 &&
                   i + 1 < (unsigned long)argc) {
            tamper_byte =
                parse_ulong(argv[++i], "tamper byte");
        } else if (strcmp(argv[i], "--tamper-mask") == 0 &&
                   i + 1 < (unsigned long)argc) {
            tamper_mask =
                parse_ulong(argv[++i], "tamper mask");
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
                "[--tamper-byte B] [--tamper-mask M]\n",
                argv[0]);
            goto cleanup;
        }
    }

    if (output_path == NULL ||
        key_path == NULL ||
        samples == 0) {
        fprintf(
            stderr,
            "[error] --output, --key-file, and samples > 0 "
            "are required\n");
        goto cleanup;
    }

    if (tamper_byte >=
        PQCLEAN_KYBER512_CLEAN_CRYPTO_CIPHERTEXTBYTES) {
        fprintf(
            stderr,
            "[error] tamper byte out of range: "
            "%lu/%u\n",
            tamper_byte,
            (unsigned int)
                PQCLEAN_KYBER512_CLEAN_CRYPTO_CIPHERTEXTBYTES);
        goto cleanup;
    }

    if (tamper_mask == 0 || tamper_mask > 0xffu) {
        fprintf(
            stderr,
            "[error] tamper mask must be in 1..255\n");
        goto cleanup;
    }

    pk = malloc(
        PQCLEAN_KYBER512_CLEAN_CRYPTO_PUBLICKEYBYTES);
    sk = malloc(
        PQCLEAN_KYBER512_CLEAN_CRYPTO_SECRETKEYBYTES);
    ct = malloc(
        PQCLEAN_KYBER512_CLEAN_CRYPTO_CIPHERTEXTBYTES);

    if (pk == NULL || sk == NULL || ct == NULL) {
        perror("malloc");
        goto cleanup;
    }

    if (create_key) {
        if (PQCLEAN_KYBER512_CLEAN_crypto_kem_keypair(
                pk, sk) != 0) {
            fprintf(stderr,
                    "[error] keypair generation failed\n");
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

    PQCLEAN_KYBER512_CLEAN_xagawa_failure_set_measurement_enabled(0);

    /*
     * Warmup uses malformed ciphertexts too. It exercises the same failure path
     * while counters are disabled.
     */
    for (i = 0; i < warmup; ++i) {
        if (PQCLEAN_KYBER512_CLEAN_crypto_kem_enc(
                ct, ss_enc, pk) != 0) {
            fprintf(stderr, "[error] warmup encapsulation failed\n");
            goto cleanup;
        }

        tamper_ciphertext(ct, tamper_byte, tamper_mask);

        if (PQCLEAN_KYBER512_CLEAN_crypto_kem_dec(
                ss_dec, ct, sk) != 0) {
            fprintf(stderr, "[error] warmup decapsulation failed\n");
            goto cleanup;
        }
    }

    {
        int init_ret =
            PQCLEAN_KYBER512_CLEAN_xagawa_failure_hpc_init();
        if (init_ret != 0) {
            fprintf(
                stderr,
                "[error] perf_event_open initialization "
                "failed: %s (%d)\n",
                strerror(-init_ret),
                init_ret);
            goto cleanup;
        }
    }

    out = fopen(output_path, "w");
    if (out == NULL) {
        perror("open output");
        goto cleanup;
    }

    write_csv_header(out);

    for (i = 0; i < samples; ++i) {
        xagawa_failure_hpc_snapshot snap;
        xagawa_failure_audit_snapshot audit;
        int enc_ret;
        int dec_ret;
        int ss_matches_encapsulated;
        int fault_oracle;
        int semantic_valid;
        double running_percent;
        unsigned int event_index;

        enc_ret =
            PQCLEAN_KYBER512_CLEAN_crypto_kem_enc(
                ct, ss_enc, pk);

        tamper_ciphertext(ct, tamper_byte, tamper_mask);

        PQCLEAN_KYBER512_CLEAN_xagawa_failure_set_measurement_enabled(1);
        dec_ret =
            PQCLEAN_KYBER512_CLEAN_crypto_kem_dec(
                ss_dec, ct, sk);
        PQCLEAN_KYBER512_CLEAN_xagawa_failure_set_measurement_enabled(0);

        PQCLEAN_KYBER512_CLEAN_xagawa_failure_get_hpc_snapshot(
            &snap);
        PQCLEAN_KYBER512_CLEAN_xagawa_failure_get_audit_snapshot(
            &audit);

        ss_matches_encapsulated =
            memcmp(ss_enc,
                   ss_dec,
                   PQCLEAN_KYBER512_CLEAN_CRYPTO_BYTES) == 0;

        /*
         * The attack oracle is the fail-flagged execution that retains the
         * pre-cmov key candidate instead of applying fallback z.
         */
        fault_oracle =
            audit.valid &&
            audit.fail_flag == 1u &&
            audit.prekey_preserved == 1u &&
            audit.fallback_applied == 0u;

#if XAGAWA_FAILURE_BUILD_MODE == XAGAWA_FAILURE_MODE_BASELINE
        semantic_valid =
            enc_ret == 0 &&
            dec_ret == 0 &&
            audit.valid &&
            audit.fail_flag == 1u &&
            audit.cmov_len == KYBER_SYMBYTES &&
            audit.prekey_preserved == 0u &&
            audit.fallback_applied == 1u &&
            !fault_oracle;
#else
        semantic_valid =
            enc_ret == 0 &&
            dec_ret == 0 &&
            audit.valid &&
            audit.fail_flag == 1u &&
            audit.cmov_len == KYBER_SYMBYTES &&
            audit.prekey_preserved == 1u &&
            audit.fallback_applied == 0u &&
            fault_oracle;
#endif

        running_percent =
            snap.time_enabled == 0
                ? 0.0
                : 100.0 *
                  (double)snap.time_running /
                  (double)snap.time_enabled;

        fprintf(
            out,
            "%lu,%s,%lu,0x%02lx,"
            "%d,%d,%d,%d,%d,"
            "%" PRIu32 ",%" PRIu32 ","
            "%" PRIu32 ",%" PRIu32 ","
            "%" PRIu64 ",%" PRIu64 ","
            "%" PRIu64 ",%" PRIu64 ",%.6f,"
            "0x%08" PRIx32 ",%" PRId32,
            i,
            PQCLEAN_KYBER512_CLEAN_xagawa_failure_mode_name(),
            tamper_byte,
            tamper_mask,
            enc_ret,
            dec_ret,
            ss_matches_encapsulated,
            fault_oracle,
            semantic_valid,
            audit.fail_flag,
            audit.cmov_len,
            audit.prekey_preserved,
            audit.fallback_applied,
            snap.sequence,
            snap.failure_handling_invocations,
            snap.time_enabled,
            snap.time_running,
            running_percent,
            snap.valid_mask,
            snap.error_code);

        for (event_index = 0;
             event_index < XAGAWA_FAILURE_HPC_EVENT_COUNT;
             ++event_index) {
            fprintf(
                out,
                ",%" PRIu64,
                snap.values[event_index]);
        }
        fputc('\n', out);
    }

    fflush(out);
    fprintf(
        stderr,
        "[done] mode=%s samples=%lu tamper=(%lu,0x%02lx) "
        "output=%s\n",
        PQCLEAN_KYBER512_CLEAN_xagawa_failure_mode_name(),
        samples,
        tamper_byte,
        tamper_mask,
        output_path);

    ret = EXIT_SUCCESS;

cleanup:
    PQCLEAN_KYBER512_CLEAN_xagawa_failure_set_measurement_enabled(0);
    PQCLEAN_KYBER512_CLEAN_xagawa_failure_hpc_close();

    if (out != NULL) {
        fclose(out);
    }
    free(ct);
    free(sk);
    free(pk);
    return ret;
}
