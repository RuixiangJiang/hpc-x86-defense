#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARRAY_SIZE (1u << 20)
static volatile uint64_t sink;

static uint64_t parse_u64(const char *s)
{
    char *end = NULL;
    unsigned long long value;

    errno = 0;
    value = strtoull(s, &end, 0);
    if (errno != 0 || end == s || *end != '\0') {
        fprintf(stderr, "invalid integer: %s\n", s);
        exit(EXIT_FAILURE);
    }
    return (uint64_t)value;
}

__attribute__((noinline))
static void baseline(uint32_t *a, uint64_t iterations)
{
    uint64_t acc = 0x9e3779b97f4a7c15ULL;
    for (uint64_t i = 0; i < iterations; ++i) {
        uint32_t index = (uint32_t)((i * 64u) & (ARRAY_SIZE - 1u));
        uint32_t value = a[index];
        if ((value & 7u) != 0u) {
            acc ^= (uint64_t)value << (i & 31u);
        } else {
            acc += value + i;
        }
    }
    sink ^= acc;
}

__attribute__((noinline))
static void source_fault_model(uint32_t *a, uint64_t iterations)
{
    uint64_t acc = 0x9e3779b97f4a7c15ULL;
    for (uint64_t i = 0; i < iterations; ++i) {
        /* Framework-validation model only: changes branches and locality. */
        uint32_t index = (uint32_t)((i * 4099u) & (ARRAY_SIZE - 1u));
        uint32_t value = a[index];
        if (((value ^ (uint32_t)i) & 3u) == 0u) {
            acc += value;
        } else if ((value & 1u) != 0u) {
            acc ^= (uint64_t)value << (i & 31u);
        } else {
            acc -= value;
        }
    }
    sink ^= acc;
}

int main(int argc, char **argv)
{
    const char *mode = "baseline";
    uint64_t iterations = 200000;
    uint32_t *array;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            mode = argv[++i];
        } else if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
            iterations = parse_u64(argv[++i]);
        } else {
            fprintf(stderr,
                    "usage: %s [--mode baseline|source-fault] [--iterations N]\n",
                    argv[0]);
            return EXIT_FAILURE;
        }
    }

    array = aligned_alloc(64, ARRAY_SIZE * sizeof(*array));
    if (array == NULL) {
        perror("aligned_alloc");
        return EXIT_FAILURE;
    }

    for (uint32_t i = 0; i < ARRAY_SIZE; ++i) {
        array[i] = i * 2654435761u ^ 0xa5a5a5a5u;
    }

    if (strcmp(mode, "baseline") == 0) {
        baseline(array, iterations);
    } else if (strcmp(mode, "source-fault") == 0) {
        source_fault_model(array, iterations);
    } else {
        fprintf(stderr, "unknown mode: %s\n", mode);
        free(array);
        return EXIT_FAILURE;
    }

    printf("mode=%s iterations=%" PRIu64 " sink=%" PRIu64 "\n",
           mode, iterations, sink);
    free(array);
    return EXIT_SUCCESS;
}
