#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "api.h"
#include "params.h"
#include "roulette_masked_invntt_x86.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define KEY_MAGIC "ROULK768"
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
        fprintf(
            stderr,
            "[error] invalid %s: %s\n",
            name,
            text);
        exit(EXIT_FAILURE);
    }
    return value;
}

static int write_all(
    int fd,
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

static int read_all(
    int fd,
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

static int save_key_file(
    const char *path,
    const uint8_t *pk,
    const uint8_t *sk)
{
    key_header hdr;
    int fd;

    memcpy(hdr.magic, KEY_MAGIC, KEY_MAGIC_LEN);
    hdr.pk_len =
        PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES;
    hdr.sk_len =
        PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES;

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
            PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES) != 0 ||
        write_all(
            fd,
            sk,
            PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES) != 0) {
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
            PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES ||
        hdr.sk_len !=
            PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES ||
        read_all(
            fd,
            pk,
            PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES) != 0 ||
        read_all(
            fd,
            sk,
            PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES) != 0) {
        int saved = errno != 0 ? errno : EINVAL;
        close(fd);
        errno = saved;
        return -1;
    }

    return close(fd);
}

static uint8_t get_v_symbol(
    const uint8_t ct[KYBER_CIPHERTEXTBYTES],
    unsigned int target)
{
    size_t offset =
        (size_t)KYBER_POLYVECCOMPRESSEDBYTES +
        (size_t)(target >> 1);
    unsigned int shift = (target & 1u) * 4u;

    return (uint8_t)((ct[offset] >> shift) & 0x0fu);
}

/*
 * Exact Eq. (12) chosen-ciphertext manipulation for Kyber768:
 *
 *     v*_i = v_i + 2^(delta_v-2) mod 2^delta_v
 *          = v_i + 4 mod 16
 */
static void manipulate_v_symbol(
    uint8_t ct[KYBER_CIPHERTEXTBYTES],
    unsigned int target)
{
    size_t offset =
        (size_t)KYBER_POLYVECCOMPRESSEDBYTES +
        (size_t)(target >> 1);
    unsigned int shift = (target & 1u) * 4u;
    uint8_t mask = (uint8_t)(0x0fu << shift);
    uint8_t old_symbol =
        (uint8_t)((ct[offset] >> shift) & 0x0fu);
    uint8_t new_symbol =
        (uint8_t)((old_symbol + 4u) & 0x0fu);

    ct[offset] =
        (uint8_t)((ct[offset] & (uint8_t)~mask) |
                  (uint8_t)(new_symbol << shift));
}

static uint32_t sample_mask_seed(
    uint32_t base_seed,
    unsigned long sample)
{
    uint32_t x =
        base_seed ^
        (uint32_t)(UINT32_C(0x9e3779b9) *
                   (uint32_t)(sample + 1u));

    x ^= x >> 16;
    x *= UINT32_C(0x7feb352d);
    x ^= x >> 15;
    x *= UINT32_C(0x846ca68b);
    x ^= x >> 16;

    return x != 0u ? x : UINT32_C(0x6d2b79f5);
}

static void write_csv_header(FILE *out)
{
    unsigned int i;

    fputs(
        "sample,mode,target_coeff,mask_seed,"
        "enc_ret,dec_ret,"
        "original_v_symbol,manipulated_v_symbol,"
        "reencrypted_v_symbol,target_symbol_match,"
        "compare_fail,oracle_success,"
        "share_a_before,share_b_before,"
        "share_normal_sum,share_used_sum,"
        "reference_coeff_mod_q,observed_coeff_mod_q,"
        "target_changed,non_target_mismatches,"
        "operation_skipped,semantic_valid,"
        "sequence,reencrypt_invocations,"
        "time_enabled,time_running,running_percent,"
        "valid_mask,error_code",
        out);

    for (i = 0; i < ROULETTE_HPC_EVENT_COUNT; ++i) {
        fprintf(
            out,
            ",%s",
            PQCLEAN_KYBER768_CLEAN_roulette_event_name(i));
    }

    fputc('\n', out);
}

int main(int argc, char **argv)
{
    uint8_t *pk = NULL;
    uint8_t *sk = NULL;
    uint8_t *ct_original = NULL;
    uint8_t *ct_manipulated = NULL;
    uint8_t ss_enc[
        PQCLEAN_KYBER768_CLEAN_CRYPTO_BYTES];
    uint8_t ss_dec[
        PQCLEAN_KYBER768_CLEAN_CRYPTO_BYTES];

    const char *output_path = NULL;
    const char *key_path = NULL;
    unsigned long samples = 500;
    unsigned long warmup = 10;
    unsigned long target_coeff = 17;
    unsigned long base_seed = UINT32_C(0x524f554c);
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
        } else if (strcmp(argv[i], "--target-coeff") == 0 &&
                   i + 1 < (unsigned long)argc) {
            target_coeff =
                parse_ulong(argv[++i], "target coefficient");
        } else if (strcmp(argv[i], "--seed") == 0 &&
                   i + 1 < (unsigned long)argc) {
            base_seed = parse_ulong(argv[++i], "seed");
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
                "[--target-coeff C] [--seed S]\n",
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

    /*
     * Table-4 instruction 2 corrupts c outputs in the final INTT layer,
     * which occupy indices 0..127 in this implementation.
     */
    if (target_coeff >= 128u) {
        fprintf(
            stderr,
            "[error] target coefficient must be in [0, 128) "
            "for the skipped final-layer share addition: %lu\n",
            target_coeff);
        goto cleanup;
    }

    pk = malloc(
        PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES);
    sk = malloc(
        PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES);
    ct_original = malloc(
        PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ct_manipulated = malloc(
        PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES);

    if (pk == NULL ||
        sk == NULL ||
        ct_original == NULL ||
        ct_manipulated == NULL) {
        perror("malloc");
        goto cleanup;
    }

    if (create_key) {
        if (PQCLEAN_KYBER768_CLEAN_crypto_kem_keypair(
                pk,
                sk) != 0) {
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

    PQCLEAN_KYBER768_CLEAN_roulette_set_target(
        (unsigned int)target_coeff);
    PQCLEAN_KYBER768_CLEAN_roulette_set_measurement_enabled(0);

    /*
     * Warm up the same chosen-ciphertext and masked-re-encryption path,
     * with counters disabled.
     */
    for (i = 0; i < warmup; ++i) {
        if (PQCLEAN_KYBER768_CLEAN_crypto_kem_enc(
                ct_original,
                ss_enc,
                pk) != 0) {
            fprintf(stderr, "[error] warmup encapsulation failed\n");
            goto cleanup;
        }

        memcpy(
            ct_manipulated,
            ct_original,
            PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES);
        manipulate_v_symbol(
            ct_manipulated,
            (unsigned int)target_coeff);

        PQCLEAN_KYBER768_CLEAN_roulette_set_mask_seed(
            sample_mask_seed(
                (uint32_t)base_seed ^ UINT32_C(0xa5a5a5a5),
                i));

        if (PQCLEAN_KYBER768_CLEAN_crypto_kem_dec(
                ss_dec,
                ct_manipulated,
                sk) != 0) {
            fprintf(stderr, "[error] warmup decapsulation failed\n");
            goto cleanup;
        }
    }

    {
        int init_ret =
            PQCLEAN_KYBER768_CLEAN_roulette_hpc_init();

        if (init_ret != 0) {
            fprintf(
                stderr,
                "[error] perf_event_open initialization failed: "
                "%s (%d)\n",
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
        roulette_hpc_snapshot snap;
        roulette_audit_snapshot audit;
        uint8_t original_symbol;
        uint8_t manipulated_symbol;
        uint32_t mask_seed;
        int enc_ret;
        int dec_ret;
        int semantic_valid;
        double running_percent;
        unsigned int event_index;

        enc_ret =
            PQCLEAN_KYBER768_CLEAN_crypto_kem_enc(
                ct_original,
                ss_enc,
                pk);

        memcpy(
            ct_manipulated,
            ct_original,
            PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES);

        original_symbol =
            get_v_symbol(
                ct_manipulated,
                (unsigned int)target_coeff);
        manipulate_v_symbol(
            ct_manipulated,
            (unsigned int)target_coeff);
        manipulated_symbol =
            get_v_symbol(
                ct_manipulated,
                (unsigned int)target_coeff);

        mask_seed =
            sample_mask_seed((uint32_t)base_seed, i);
        PQCLEAN_KYBER768_CLEAN_roulette_set_mask_seed(
            mask_seed);

        PQCLEAN_KYBER768_CLEAN_roulette_set_measurement_enabled(1);
        dec_ret =
            PQCLEAN_KYBER768_CLEAN_crypto_kem_dec(
                ss_dec,
                ct_manipulated,
                sk);
        PQCLEAN_KYBER768_CLEAN_roulette_set_measurement_enabled(0);

        PQCLEAN_KYBER768_CLEAN_roulette_get_hpc_snapshot(
            &snap);
        PQCLEAN_KYBER768_CLEAN_roulette_get_audit_snapshot(
            &audit);

        semantic_valid =
            enc_ret == 0 &&
            dec_ret == 0 &&
            audit.valid &&
            audit.compare_recorded &&
            audit.target_coeff == target_coeff &&
            manipulated_symbol ==
                (uint8_t)((original_symbol + 4u) & 0x0fu) &&
            audit.input_v_symbol == manipulated_symbol;

#if ROULETTE_BUILD_MODE == ROULETTE_MODE_BASELINE
        semantic_valid =
            semantic_valid &&
            audit.operation_skipped == 0u &&
            audit.share_used_sum == audit.share_normal_sum &&
            audit.target_changed == 0u;
#else
        semantic_valid =
            semantic_valid &&
            audit.operation_skipped == 1u &&
            audit.share_used_sum == audit.share_a_before;
#endif

        running_percent =
            snap.time_enabled == 0
                ? 0.0
                : 100.0 *
                  (double)snap.time_running /
                  (double)snap.time_enabled;

        fprintf(
            out,
            "%lu,%s,%lu,0x%08" PRIx32 ","
            "%d,%d,"
            "%u,%u,%u,%u,"
            "%u,%u,"
            "%" PRId32 ",%" PRId32 ","
            "%" PRId32 ",%" PRId32 ","
            "%" PRId32 ",%" PRId32 ","
            "%u,%u,%u,%d,"
            "%" PRIu64 ",%" PRIu64 ","
            "%" PRIu64 ",%" PRIu64 ",%.6f,"
            "0x%08" PRIx32 ",%" PRId32,
            i,
            PQCLEAN_KYBER768_CLEAN_roulette_mode_name(),
            target_coeff,
            mask_seed,
            enc_ret,
            dec_ret,
            original_symbol,
            manipulated_symbol,
            audit.reencrypted_v_symbol,
            audit.target_symbol_match,
            audit.compare_fail,
            audit.oracle_success,
            audit.share_a_before,
            audit.share_b_before,
            audit.share_normal_sum,
            audit.share_used_sum,
            audit.reference_coeff_mod_q,
            audit.observed_coeff_mod_q,
            audit.target_changed,
            audit.non_target_mismatches,
            audit.operation_skipped,
            semantic_valid,
            snap.sequence,
            snap.reencrypt_invocations,
            snap.time_enabled,
            snap.time_running,
            running_percent,
            snap.valid_mask,
            snap.error_code);

        for (event_index = 0;
             event_index < ROULETTE_HPC_EVENT_COUNT;
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
        "[done] mode=%s samples=%lu target=%lu output=%s\n",
        PQCLEAN_KYBER768_CLEAN_roulette_mode_name(),
        samples,
        target_coeff,
        output_path);

    ret = EXIT_SUCCESS;

cleanup:
    PQCLEAN_KYBER768_CLEAN_roulette_set_measurement_enabled(0);
    PQCLEAN_KYBER768_CLEAN_roulette_set_reencrypt_active(0);
    PQCLEAN_KYBER768_CLEAN_roulette_hpc_close();

    if (out != NULL) {
        fclose(out);
    }

    free(ct_manipulated);
    free(ct_original);
    free(sk);
    free(pk);

    return ret;
}
