#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "api.h"
#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "signature_correction_x86.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define KEY_MAGIC "SCORR001"
#define KEY_MAGIC_LEN 8u

typedef struct {
    char magic[KEY_MAGIC_LEN];
    uint64_t pk_len;
    uint64_t sk_len;
} key_header;

typedef struct {
    int found;
    unsigned int target_vec;
    unsigned int target_coeff;
    unsigned int bit_index;
    unsigned int recovered_bit;
    int correction_sign;
    unsigned long verifications;
} search_result;

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
        PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES;
    hdr.sk_len =
        PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES;

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

static void build_message(
    uint8_t message[64],
    uint32_t domain,
    uint64_t sample,
    uint32_t attempt)
{
    static const uint8_t prefix[] =
        "Islam et al. Signature Correction Dilithium2";
    size_t prefix_len = sizeof(prefix) - 1u;

    memset(message, 0, 64);
    if (prefix_len > 40u) {
        prefix_len = 40u;
    }
    memcpy(message, prefix, prefix_len);

    message[40] = (uint8_t)(domain >> 0);
    message[41] = (uint8_t)(domain >> 8);
    message[42] = (uint8_t)(domain >> 16);
    message[43] = (uint8_t)(domain >> 24);

    message[44] = (uint8_t)(sample >> 0);
    message[45] = (uint8_t)(sample >> 8);
    message[46] = (uint8_t)(sample >> 16);
    message[47] = (uint8_t)(sample >> 24);
    message[48] = (uint8_t)(sample >> 32);
    message[49] = (uint8_t)(sample >> 40);
    message[50] = (uint8_t)(sample >> 48);
    message[51] = (uint8_t)(sample >> 56);

    message[52] = (uint8_t)(attempt >> 0);
    message[53] = (uint8_t)(attempt >> 8);
    message[54] = (uint8_t)(attempt >> 16);
    message[55] = (uint8_t)(attempt >> 24);
}

static void shift_challenge(
    poly *shifted,
    const poly *challenge,
    unsigned int coefficient)
{
    unsigned int i;

    memset(shifted, 0, sizeof(*shifted));

    for (i = 0; i < (unsigned int)N; ++i) {
        unsigned int index = i + coefficient;
        int32_t value = challenge->coeffs[i];

        if (index >= (unsigned int)N) {
            index -= (unsigned int)N;
            value = -value;
        }

        shifted->coeffs[index] = value;
    }
}

static int make_corrected_signature(
    uint8_t corrected[PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES],
    const uint8_t faulty[PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES],
    int64_t correction_delta,
    unsigned int target_vec,
    unsigned int target_coeff)
{
    uint8_t challenge_seed[SEEDBYTES];
    poly challenge;
    poly shifted;
    polyvecl z;
    polyveck h;
    unsigned int i;

    if (target_vec >= (unsigned int)L ||
        target_coeff >= (unsigned int)N) {
        return -1;
    }

    if (PQCLEAN_DILITHIUM2_CLEAN_unpack_sig(
            challenge_seed,
            &z,
            &h,
            faulty) != 0) {
        return -1;
    }

    PQCLEAN_DILITHIUM2_CLEAN_poly_challenge(
        &challenge,
        challenge_seed);
    shift_challenge(
        &shifted,
        &challenge,
        target_coeff);

    for (i = 0; i < (unsigned int)N; ++i) {
        int64_t value =
            (int64_t)z.vec[target_vec].coeffs[i] +
            correction_delta *
                (int64_t)shifted.coeffs[i];

        if (value < INT32_MIN || value > INT32_MAX) {
            return -1;
        }

        z.vec[target_vec].coeffs[i] = (int32_t)value;
    }

    PQCLEAN_DILITHIUM2_CLEAN_pack_sig(
        corrected,
        challenge_seed,
        &z,
        &h);
    return 0;
}

static int verify_corrected_delta(
    const uint8_t faulty[PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES],
    uint8_t corrected[PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES],
    int64_t correction_delta,
    unsigned int target_vec,
    unsigned int target_coeff,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *pk)
{
    if (make_corrected_signature(
            corrected,
            faulty,
            correction_delta,
            target_vec,
            target_coeff) != 0) {
        return -1;
    }

    return PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify(
        corrected,
        PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES,
        message,
        message_len,
        pk);
}

static search_result search_signature_correction(
    const uint8_t faulty[PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES],
    uint8_t trial[PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES],
    const uint8_t *message,
    size_t message_len,
    const uint8_t *pk,
    unsigned int search_bits)
{
    search_result result;
    unsigned int bit;
    unsigned int row;
    unsigned int col;

    memset(&result, 0, sizeof(result));

    if (search_bits > 31u) {
        search_bits = 31u;
    }

    for (bit = 0; bit < search_bits; ++bit) {
        int64_t multiplier = INT64_C(1) << bit;

        for (row = 0; row < (unsigned int)L; ++row) {
            for (col = 0; col < (unsigned int)N; ++col) {
                result.verifications++;
                if (verify_corrected_delta(
                        faulty,
                        trial,
                        multiplier,
                        row,
                        col,
                        message,
                        message_len,
                        pk) == 0) {
                    result.found = 1;
                    result.target_vec = row;
                    result.target_coeff = col;
                    result.bit_index = bit;
                    result.recovered_bit = 1u;
                    result.correction_sign = 1;
                    return result;
                }

                result.verifications++;
                if (verify_corrected_delta(
                        faulty,
                        trial,
                        -multiplier,
                        row,
                        col,
                        message,
                        message_len,
                        pk) == 0) {
                    result.found = 1;
                    result.target_vec = row;
                    result.target_coeff = col;
                    result.bit_index = bit;
                    result.recovered_bit = 0u;
                    result.correction_sign = -1;
                    return result;
                }
            }
        }
    }

    return result;
}

static void write_csv_header(FILE *out)
{
    unsigned int i;

    fputs(
        "sample,mode,message_domain,attempts,"
        "target_vec,target_coeff,bit_index,"
        "sign_ret,faulty_verify_ret,"
        "direct_correction_ret,direct_correction_delta,"
        "original_value,faulty_value,"
        "original_word,faulty_word,xor_mask,"
        "original_bit,faulty_bit,hamming_distance,"
        "fault_requested,fault_applied,"
        "search_performed,search_found,"
        "search_vec,search_coeff,search_bit,"
        "search_recovered_value,search_correction_sign,"
        "search_verifications,semantic_valid,"
        "sequence,signing_invocations,"
        "time_enabled,time_running,running_percent,"
        "valid_mask,error_code",
        out);

    for (i = 0; i < SIGNCORR_HPC_EVENT_COUNT; ++i) {
        fprintf(
            out,
            ",%s",
            PQCLEAN_DILITHIUM2_CLEAN_signcorr_event_name(i));
    }

    fputc('\n', out);
}

int main(int argc, char **argv)
{
    uint8_t *pk = NULL;
    uint8_t *sk = NULL;
    uint8_t *sig = NULL;
    uint8_t *corrected = NULL;
    uint8_t message[64];

    const char *output_path = NULL;
    const char *key_path = NULL;

    unsigned long samples = 500;
    unsigned long warmup = 10;
    unsigned long fault_enable = 0;
    unsigned long target_vec = 0;
    unsigned long target_coeff = 17;
    unsigned long bit_index = 0;
    unsigned long message_domain = UINT32_C(0x53434731);
    unsigned long max_attempts = 128;
    unsigned long full_search_first = 0;
    unsigned long search_bits = 3;
    int create_key = 0;

    FILE *out = NULL;
    size_t siglen = 0;
    unsigned long i;
    int ret = EXIT_FAILURE;

    for (i = 1; i < (unsigned long)argc; ++i) {
        if (strcmp(argv[i], "--samples") == 0 &&
            i + 1 < (unsigned long)argc) {
            samples = parse_ulong(argv[++i], "samples");
        } else if (strcmp(argv[i], "--warmup") == 0 &&
                   i + 1 < (unsigned long)argc) {
            warmup = parse_ulong(argv[++i], "warmup");
        } else if (strcmp(argv[i], "--fault-enable") == 0 &&
                   i + 1 < (unsigned long)argc) {
            fault_enable =
                parse_ulong(argv[++i], "fault enable");
        } else if (strcmp(argv[i], "--target-vec") == 0 &&
                   i + 1 < (unsigned long)argc) {
            target_vec =
                parse_ulong(argv[++i], "target vector");
        } else if (strcmp(argv[i], "--target-coeff") == 0 &&
                   i + 1 < (unsigned long)argc) {
            target_coeff =
                parse_ulong(argv[++i], "target coefficient");
        } else if (strcmp(argv[i], "--bit-index") == 0 &&
                   i + 1 < (unsigned long)argc) {
            bit_index =
                parse_ulong(argv[++i], "bit index");
        } else if (strcmp(argv[i], "--message-domain") == 0 &&
                   i + 1 < (unsigned long)argc) {
            message_domain =
                parse_ulong(argv[++i], "message domain");
        } else if (strcmp(argv[i], "--max-attempts") == 0 &&
                   i + 1 < (unsigned long)argc) {
            max_attempts =
                parse_ulong(argv[++i], "max attempts");
        } else if (strcmp(argv[i], "--full-search-first") == 0) {
            full_search_first = 1;
        } else if (strcmp(argv[i], "--search-bits") == 0 &&
                   i + 1 < (unsigned long)argc) {
            search_bits =
                parse_ulong(argv[++i], "search bits");
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
                "[--fault-enable 0|1] [--target-vec V] "
                "[--target-coeff C] [--bit-index B] "
                "[--message-domain D] [--max-attempts N] "
                "[--full-search-first] [--search-bits B]\n",
                argv[0]);
            goto cleanup;
        }
    }

    if (output_path == NULL ||
        key_path == NULL ||
        samples == 0 ||
        max_attempts == 0) {
        fprintf(
            stderr,
            "[error] output, key file, samples, and max attempts "
            "must be valid\n");
        goto cleanup;
    }

    if (fault_enable > 1u ||
        target_vec >= (unsigned long)L ||
        target_coeff >= (unsigned long)N ||
        bit_index >= 32u ||
        search_bits == 0u ||
        search_bits > 31u) {
        fprintf(stderr, "[error] invalid fault/search configuration\n");
        goto cleanup;
    }

    pk = malloc(
        PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES);
    sk = malloc(
        PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES);
    sig = malloc(
        PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES);
    corrected = malloc(
        PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES);

    if (pk == NULL ||
        sk == NULL ||
        sig == NULL ||
        corrected == NULL) {
        perror("malloc");
        goto cleanup;
    }

    if (create_key) {
        if (PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair(
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

    PQCLEAN_DILITHIUM2_CLEAN_signcorr_configure(
        (int)fault_enable,
        (unsigned int)target_vec,
        (unsigned int)target_coeff,
        (unsigned int)bit_index);
    PQCLEAN_DILITHIUM2_CLEAN_signcorr_set_measurement_enabled(0);

    for (i = 0; i < warmup; ++i) {
        build_message(
            message,
            (uint32_t)message_domain ^ UINT32_C(0x57524d55),
            i,
            0);

        if (PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature(
                sig,
                &siglen,
                message,
                sizeof(message),
                sk) != 0) {
            fprintf(stderr, "[error] warmup signing failed\n");
            goto cleanup;
        }
    }

    {
        int init_ret =
            PQCLEAN_DILITHIUM2_CLEAN_signcorr_hpc_init();

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
        signcorr_hpc_snapshot snap;
        signcorr_audit_snapshot audit;
        search_result search;
        unsigned long attempt;
        int sign_ret = -1;
        int faulty_verify_ret = -1;
        int direct_correction_ret = -1;
        int semantic_valid = 0;
        int64_t correction_delta = 0;
        double running_percent;
        unsigned int event_index;
        int search_performed = 0;

        memset(&search, 0, sizeof(search));

        for (attempt = 1; attempt <= max_attempts; ++attempt) {
            build_message(
                message,
                (uint32_t)message_domain,
                i,
                (uint32_t)attempt);

            PQCLEAN_DILITHIUM2_CLEAN_signcorr_configure(
                (int)fault_enable,
                (unsigned int)target_vec,
                (unsigned int)target_coeff,
                (unsigned int)bit_index);

            PQCLEAN_DILITHIUM2_CLEAN_signcorr_set_measurement_enabled(1);
            sign_ret =
                PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature(
                    sig,
                    &siglen,
                    message,
                    sizeof(message),
                    sk);
            PQCLEAN_DILITHIUM2_CLEAN_signcorr_set_measurement_enabled(0);

            PQCLEAN_DILITHIUM2_CLEAN_signcorr_get_hpc_snapshot(
                &snap);
            PQCLEAN_DILITHIUM2_CLEAN_signcorr_get_audit_snapshot(
                &audit);

            faulty_verify_ret =
                PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify(
                    sig,
                    siglen,
                    message,
                    sizeof(message),
                    pk);

            correction_delta =
                (int64_t)audit.original_value -
                (int64_t)audit.faulty_value;

            if (fault_enable != 0u) {
                direct_correction_ret =
                    verify_corrected_delta(
                        sig,
                        corrected,
                        correction_delta,
                        (unsigned int)target_vec,
                        (unsigned int)target_coeff,
                        message,
                        sizeof(message),
                        pk);
            } else {
                direct_correction_ret = -999;
            }

            semantic_valid =
                sign_ret == 0 &&
                siglen ==
                    PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES &&
                audit.valid &&
                audit.target_vec == target_vec &&
                audit.target_coeff == target_coeff &&
                audit.bit_index == bit_index;

            if (fault_enable == 0u) {
                semantic_valid =
                    semantic_valid &&
                    faulty_verify_ret == 0 &&
                    audit.fault_applied == 0u &&
                    correction_delta == 0;
            } else {
                semantic_valid =
                    semantic_valid &&
                    faulty_verify_ret != 0 &&
                    audit.fault_applied == 1u &&
                    audit.hamming_distance == 1u &&
                    direct_correction_ret == 0;
            }

            if (semantic_valid) {
                break;
            }
        }

        if (!semantic_valid) {
            fprintf(
                stderr,
                "[error] unable to obtain a semantically valid "
                "sample %lu in %lu attempts\n",
                i,
                max_attempts);
            goto cleanup;
        }

        if (fault_enable != 0u &&
            full_search_first != 0u &&
            i == 0u) {
            search_performed = 1;
            search =
                search_signature_correction(
                    sig,
                    corrected,
                    message,
                    sizeof(message),
                    pk,
                    (unsigned int)search_bits);

            semantic_valid =
                semantic_valid &&
                search.found &&
                search.target_vec == target_vec &&
                search.target_coeff == target_coeff &&
                search.bit_index == bit_index &&
                search.recovered_bit == audit.original_bit;
        }

        running_percent =
            snap.time_enabled == 0
                ? 0.0
                : 100.0 *
                  (double)snap.time_running /
                  (double)snap.time_enabled;

        fprintf(
            out,
            "%lu,%s,0x%08lx,%lu,"
            "%lu,%lu,%lu,"
            "%d,%d,%d,%" PRId64 ","
            "%" PRId32 ",%" PRId32 ","
            "0x%08" PRIx32 ",0x%08" PRIx32 ",0x%08" PRIx32 ","
            "%u,%u,%u,%u,%u,"
            "%d,%d,%u,%u,%u,%u,%d,%lu,%d,"
            "%" PRIu64 ",%" PRIu64 ","
            "%" PRIu64 ",%" PRIu64 ",%.6f,"
            "0x%08" PRIx32 ",%" PRId32,
            i,
            fault_enable != 0u
                ? "single-bit-flip"
                : "baseline",
            message_domain,
            attempt,
            target_vec,
            target_coeff,
            bit_index,
            sign_ret,
            faulty_verify_ret,
            direct_correction_ret,
            correction_delta,
            audit.original_value,
            audit.faulty_value,
            audit.original_word,
            audit.faulty_word,
            audit.xor_mask,
            audit.original_bit,
            audit.faulty_bit,
            audit.hamming_distance,
            audit.fault_requested,
            audit.fault_applied,
            search_performed,
            search.found,
            search.target_vec,
            search.target_coeff,
            search.bit_index,
            search.recovered_bit,
            search.correction_sign,
            search.verifications,
            semantic_valid,
            snap.sequence,
            snap.signing_invocations,
            snap.time_enabled,
            snap.time_running,
            running_percent,
            snap.valid_mask,
            snap.error_code);

        for (event_index = 0;
             event_index < SIGNCORR_HPC_EVENT_COUNT;
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
        "[done] mode=%s samples=%lu target=(%lu,%lu) "
        "bit=%lu output=%s\n",
        fault_enable != 0u
            ? "single-bit-flip"
            : "baseline",
        samples,
        target_vec,
        target_coeff,
        bit_index,
        output_path);

    ret = EXIT_SUCCESS;

cleanup:
    PQCLEAN_DILITHIUM2_CLEAN_signcorr_set_measurement_enabled(0);
    PQCLEAN_DILITHIUM2_CLEAN_signcorr_hpc_close();

    if (out != NULL) {
        fclose(out);
    }

    free(corrected);
    free(sig);
    free(sk);
    free(pk);

    return ret;
}
