#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "api.h"
#include "fips202.h"
#include "jendral_hedged_fault_x86.h"
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

#ifndef JENDRAL_ATTACK_BUILD
#define JENDRAL_ATTACK_BUILD 0
#endif

#define KEY_MAGIC "JENDRAL1"
#define KEY_MAGIC_LEN 8u

typedef struct {
    char magic[KEY_MAGIC_LEN];
    uint64_t pk_len;
    uint64_t sk_len;
} key_header;

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

static int save_key_file(const char *path, const uint8_t *pk, const uint8_t *sk)
{
    key_header hdr;
    int fd;

    memcpy(hdr.magic, KEY_MAGIC, KEY_MAGIC_LEN);
    hdr.pk_len = PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES;
    hdr.sk_len = PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return -1;
    }
    if (write_all(fd, &hdr, sizeof(hdr)) != 0 ||
        write_all(fd, pk, PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES) != 0 ||
        write_all(fd, sk, PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return close(fd);
}

static int load_key_file(const char *path, uint8_t *pk, uint8_t *sk)
{
    key_header hdr;
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    if (read_all(fd, &hdr, sizeof(hdr)) != 0 ||
        memcmp(hdr.magic, KEY_MAGIC, KEY_MAGIC_LEN) != 0 ||
        hdr.pk_len != PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES ||
        hdr.sk_len != PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES ||
        read_all(fd, pk, PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES) != 0 ||
        read_all(fd, sk, PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES) != 0) {
        int saved = errno != 0 ? errno : EINVAL;
        close(fd);
        errno = saved;
        return -1;
    }
    return close(fd);
}

static void build_message(uint8_t message[64], uint32_t domain, uint64_t sample)
{
    static const uint8_t prefix[] =
        "Jendral single-trace hedged Dilithium fault";
    size_t prefix_len = sizeof(prefix) - 1u;

    memset(message, 0, 64);
    if (prefix_len > 48u) {
        prefix_len = 48u;
    }
    memcpy(message, prefix, prefix_len);
    message[48] = (uint8_t)(domain >> 0);
    message[49] = (uint8_t)(domain >> 8);
    message[50] = (uint8_t)(domain >> 16);
    message[51] = (uint8_t)(domain >> 24);
    message[52] = (uint8_t)(sample >> 0);
    message[53] = (uint8_t)(sample >> 8);
    message[54] = (uint8_t)(sample >> 16);
    message[55] = (uint8_t)(sample >> 24);
    message[56] = (uint8_t)(sample >> 32);
    message[57] = (uint8_t)(sample >> 40);
    message[58] = (uint8_t)(sample >> 48);
    message[59] = (uint8_t)(sample >> 56);
}

static void build_public_rnd(uint8_t rnd[SEEDBYTES], uint32_t domain, uint64_t sample)
{
    uint8_t input[32];
    static const uint8_t label[] = "public hedged rnd";

    memset(input, 0, sizeof(input));
    memcpy(input, label, sizeof(label) - 1u);
    input[16] = (uint8_t)(domain >> 0);
    input[17] = (uint8_t)(domain >> 8);
    input[18] = (uint8_t)(domain >> 16);
    input[19] = (uint8_t)(domain >> 24);
    input[20] = (uint8_t)(sample >> 0);
    input[21] = (uint8_t)(sample >> 8);
    input[22] = (uint8_t)(sample >> 16);
    input[23] = (uint8_t)(sample >> 24);
    input[24] = (uint8_t)(sample >> 32);
    input[25] = (uint8_t)(sample >> 40);
    input[26] = (uint8_t)(sample >> 48);
    input[27] = (uint8_t)(sample >> 56);
    shake256(rnd, SEEDBYTES, input, sizeof(input));
}

static uint64_t signature_tag(const uint8_t *sig, size_t len)
{
    uint64_t hash = UINT64_C(1469598103934665603);
    size_t i;
    for (i = 0; i < len; ++i) {
        hash ^= sig[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static const char *mode_name(void)
{
#if JENDRAL_ATTACK_BUILD == 0
    return "baseline";
#else
    return "skip-key-absorb";
#endif
}

static void write_csv_header(FILE *out)
{
    unsigned int i;
    fputs(
        "sample,mode,message_domain,sign_ret,siglen,verify_ret,"
        "oracle_success,signature_tag,rnd_tag,mu_tag,expected_seed_tag,"
        "used_seed_tag,public_seed_tag,rnd_is_public,final_nonce,"
        "key_absorb_executed,key_absorb_skipped,seed_matches_expected,"
        "seed_matches_public,fault_requested,fault_applied,"
        "relation_mismatches,relation_valid,semantic_valid,"
        "sequence,target_invocations,time_enabled,time_running,"
        "running_percent,valid_mask,error_code",
        out);
    for (i = 0; i < JENDRAL_HPC_EVENT_COUNT; ++i) {
        fprintf(out, ",%s", PQCLEAN_DILITHIUM2_CLEAN_jendral_event_name(i));
    }
    fputc('\n', out);
}

int main(int argc, char **argv)
{
    uint8_t *pk = NULL;
    uint8_t *sk = NULL;
    uint8_t *sig = NULL;
    uint8_t message[64];
    uint8_t rnd[SEEDBYTES];
    const char *output_path = NULL;
    const char *key_path = NULL;
    unsigned long samples = 500;
    unsigned long warmup = 10;
    unsigned long message_domain = 0;
    int create_key = 0;
    FILE *out = NULL;
    unsigned long i;
    int ret = EXIT_FAILURE;

    for (i = 1; i < (unsigned long)argc; ++i) {
        if (strcmp(argv[i], "--samples") == 0 && i + 1 < (unsigned long)argc) {
            samples = parse_ulong(argv[++i], "samples");
        } else if (strcmp(argv[i], "--warmup") == 0 && i + 1 < (unsigned long)argc) {
            warmup = parse_ulong(argv[++i], "warmup");
        } else if (strcmp(argv[i], "--message-domain") == 0 && i + 1 < (unsigned long)argc) {
            message_domain = parse_ulong(argv[++i], "message domain");
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < (unsigned long)argc) {
            output_path = argv[++i];
        } else if (strcmp(argv[i], "--key-file") == 0 && i + 1 < (unsigned long)argc) {
            key_path = argv[++i];
        } else if (strcmp(argv[i], "--create-key") == 0) {
            create_key = 1;
        } else {
            fprintf(stderr,
                    "usage: %s --output FILE --key-file FILE [--create-key] "
                    "[--samples N] [--warmup N] [--message-domain D]\n",
                    argv[0]);
            goto cleanup;
        }
    }

    if (output_path == NULL || key_path == NULL || samples == 0) {
        fprintf(stderr, "[error] output, key-file, and samples > 0 are required\n");
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
            fprintf(stderr, "[error] key generation failed\n");
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

    if (PQCLEAN_DILITHIUM2_CLEAN_jendral_hpc_init() != 0) {
        fprintf(stderr, "[error] PMU initialization failed\n");
        goto cleanup;
    }

    PQCLEAN_DILITHIUM2_CLEAN_jendral_set_measurement_enabled(0);
    for (i = 0; i < warmup; ++i) {
        size_t siglen = 0;
        build_message(message, (uint32_t)message_domain, i);
        build_public_rnd(rnd, (uint32_t)message_domain, i);
        PQCLEAN_DILITHIUM2_CLEAN_jendral_set_public_randomness(rnd);
        if (PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature(
                sig, &siglen, message, sizeof(message), sk) != 0) {
            fprintf(stderr, "[error] warmup signing failed\n");
            goto cleanup;
        }
    }

    out = fopen(output_path, "w");
    if (out == NULL) {
        perror("fopen output");
        goto cleanup;
    }
    write_csv_header(out);

    for (i = 0; i < samples; ++i) {
        size_t siglen = 0;
        int sign_ret;
        int verify_ret;
        int relation_ret;
        int oracle_success;
        double running_percent;
        uint64_t sig_tag;
        jendral_hpc_snapshot hpc;
        jendral_audit_snapshot audit;
        unsigned int event;

        build_message(message, (uint32_t)message_domain, i);
        build_public_rnd(rnd, (uint32_t)message_domain, i);
        PQCLEAN_DILITHIUM2_CLEAN_jendral_set_public_randomness(rnd);
        PQCLEAN_DILITHIUM2_CLEAN_jendral_set_measurement_enabled(1);
        sign_ret = PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature(
            sig, &siglen, message, sizeof(message), sk);
        PQCLEAN_DILITHIUM2_CLEAN_jendral_set_measurement_enabled(0);

        verify_ret = sign_ret == 0
            ? PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify(
                  sig, siglen, message, sizeof(message), pk)
            : -1;
        relation_ret = sign_ret == 0
            ? PQCLEAN_DILITHIUM2_CLEAN_jendral_check_single_trace_relation(sig, sk)
            : -1;

        PQCLEAN_DILITHIUM2_CLEAN_jendral_get_hpc_snapshot(&hpc);
        PQCLEAN_DILITHIUM2_CLEAN_jendral_get_audit_snapshot(&audit);

#if JENDRAL_ATTACK_BUILD == 0
        oracle_success =
            sign_ret == 0 && verify_ret == 0 && relation_ret == 0 &&
            audit.semantic_valid && audit.seed_matches_expected &&
            !audit.seed_matches_public;
#else
        oracle_success =
            sign_ret == 0 && verify_ret == 0 && relation_ret == 0 &&
            audit.semantic_valid && audit.seed_matches_public &&
            audit.rnd_is_public;
#endif

        running_percent = hpc.time_enabled != 0
            ? 100.0 * (double)hpc.time_running / (double)hpc.time_enabled
            : 0.0;
        sig_tag = sign_ret == 0 ? signature_tag(sig, siglen) : 0;

        fprintf(out,
                "%lu,%s,%lu,%d,%zu,%d,%d,%" PRIu64 ","
                "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
                "%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,"
                "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%.9f,0x%08x,%d",
                i, mode_name(), message_domain, sign_ret, siglen, verify_ret,
                oracle_success, sig_tag,
                audit.rnd_tag, audit.mu_tag, audit.expected_seed_tag,
                audit.used_seed_tag, audit.public_seed_tag,
                audit.rnd_is_public, audit.final_nonce,
                audit.key_absorb_executed, audit.key_absorb_skipped,
                audit.seed_matches_expected, audit.seed_matches_public,
                audit.fault_requested, audit.fault_applied,
                audit.relation_mismatches, audit.relation_valid,
                audit.semantic_valid,
                hpc.sequence, hpc.target_invocations,
                hpc.time_enabled, hpc.time_running, running_percent,
                hpc.valid_mask, hpc.error_code);
        for (event = 0; event < JENDRAL_HPC_EVENT_COUNT; ++event) {
            fprintf(out, ",%" PRIu64, hpc.values[event]);
        }
        fputc('\n', out);
    }

    if (fflush(out) != 0) {
        perror("fflush");
        goto cleanup;
    }

    ret = EXIT_SUCCESS;

cleanup:
    PQCLEAN_DILITHIUM2_CLEAN_jendral_set_measurement_enabled(0);
    PQCLEAN_DILITHIUM2_CLEAN_jendral_clear_public_randomness();
    PQCLEAN_DILITHIUM2_CLEAN_jendral_hpc_close();
    if (out != NULL) {
        fclose(out);
    }
    free(sig);
    free(sk);
    free(pk);
    return ret;
}
