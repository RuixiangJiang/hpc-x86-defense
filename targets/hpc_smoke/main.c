#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CACHE_ITEMS (1u << 23) /* 32 MiB of uint32_t entries. */
#define CACHE_MASK  (CACHE_ITEMS - 1u)
#define CACHE_STRIDE 4099u     /* Odd: traverses every entry in a power-of-two array. */

static volatile uint64_t sink;

static uint64_t parse_u64(const char *text)
{
    char *end = NULL;
    unsigned long long value;

    errno = 0;
    value = strtoull(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0' || value == 0u) {
        fprintf(stderr, "invalid positive integer: %s\n", text);
        exit(EXIT_FAILURE);
    }
    return (uint64_t)value;
}

static inline uint64_t rotl64(uint64_t value, unsigned int amount)
{
    return (value << amount) | (value >> (64u - amount));
}

__attribute__((noinline))
static void compute_workload(uint64_t iterations)
{
    uint64_t x = 0x243f6a8885a308d3ULL;
    uint64_t y = 0x13198a2e03707344ULL;

    for (uint64_t i = 0; i < iterations; ++i) {
        x = x * 0x9e3779b185ebca87ULL + i + 0xd1b54a32d192ed03ULL;
        y ^= rotl64(x + y, 17u);
        x ^= y >> 11u;
        y += x ^ (i * 0x94d049bb133111ebULL);
    }

    sink ^= x ^ y;
}

/* Separate noinline leaves force real conditional control-flow instructions. */
__attribute__((noinline))
static uint64_t branch_leaf_add(uint64_t acc, uint64_t value)
{
    __asm__ __volatile__("" ::: "memory");
    return acc + value + 0x9e3779b97f4a7c15ULL;
}

__attribute__((noinline))
static uint64_t branch_leaf_xor(uint64_t acc, uint64_t value)
{
    __asm__ __volatile__("" ::: "memory");
    return acc ^ rotl64(value, 23u);
}

__attribute__((noinline))
static void branch_workload(uint64_t iterations)
{
    uint64_t state = 0x6a09e667f3bcc909ULL;
    uint64_t acc = 0xbb67ae8584caa73bULL;

    for (uint64_t i = 0; i < iterations; ++i) {
        /* xorshift state makes each condition difficult to predict. */
        state ^= state << 13u;
        state ^= state >> 7u;
        state ^= state << 17u;
        state += i * 0x9e3779b97f4a7c15ULL;

        if ((state & 0x1u) != 0u) {
            acc = branch_leaf_add(acc, state);
        } else {
            acc = branch_leaf_xor(acc, state);
        }

        if ((state & 0x2u) != 0u) {
            acc = branch_leaf_xor(acc, state + i);
        } else {
            acc = branch_leaf_add(acc, state ^ i);
        }

        if ((state & 0x4u) != 0u) {
            acc = branch_leaf_add(acc, state >> 3u);
        } else {
            acc = branch_leaf_xor(acc, state << 1u);
        }

        if ((state & 0x8u) != 0u) {
            acc = branch_leaf_xor(acc, state ^ acc);
        } else {
            acc = branch_leaf_add(acc, state + acc);
        }
    }

    sink ^= acc ^ state;
}

__attribute__((noinline))
static void cache_workload(uint64_t iterations)
{
    uint32_t *next = aligned_alloc(64u, CACHE_ITEMS * sizeof(*next));
    uint32_t index = 0u;
    uint64_t acc = 0u;
    uint64_t accesses;

    if (next == NULL) {
        perror("aligned_alloc");
        exit(EXIT_FAILURE);
    }

    /* Build a deterministic 32 MiB pointer-chasing ring. */
    for (uint32_t i = 0u; i < CACHE_ITEMS; ++i) {
        next[i] = (i + CACHE_STRIDE) & CACHE_MASK;
    }

    /* Ensure enough accesses to make cache counters unambiguously nonzero. */
    accesses = iterations * 4u;
    if (accesses < CACHE_ITEMS) {
        accesses = CACHE_ITEMS;
    }

    for (uint64_t i = 0u; i < accesses; ++i) {
        index = next[index];
        acc += (uint64_t)index + i;
    }

    sink ^= acc ^ index;
    free(next);
}

int main(int argc, char **argv)
{
    const char *mode = NULL;
    uint64_t iterations = 1000000u;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            mode = argv[++i];
        } else if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
            iterations = parse_u64(argv[++i]);
        } else {
            fprintf(stderr,
                    "usage: %s --mode compute|branch|cache [--iterations N]\n",
                    argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (mode == NULL) {
        fprintf(stderr, "missing --mode\n");
        return EXIT_FAILURE;
    }

    if (strcmp(mode, "compute") == 0) {
        compute_workload(iterations);
    } else if (strcmp(mode, "branch") == 0) {
        branch_workload(iterations);
    } else if (strcmp(mode, "cache") == 0) {
        cache_workload(iterations);
    } else {
        fprintf(stderr, "unknown mode: %s\n", mode);
        return EXIT_FAILURE;
    }

    printf("mode=%s iterations=%" PRIu64 " sink=%" PRIu64 "\n",
           mode, iterations, sink);
    return EXIT_SUCCESS;
}
