#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "breaking_the_shield_x86.h"

#include <errno.h>
#include <linux/perf_event.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef BTS_REGION
#define BTS_REGION 1
#endif

#ifndef BTS_PMU_TYPE
#define BTS_PMU_TYPE 4u
#endif

#ifndef BTS_LOAD_CONFIG
#define BTS_LOAD_CONFIG UINT64_C(0x81d0)
#endif

typedef struct {
    uint64_t value;
    uint64_t id;
} bts_read_value;

typedef struct {
    uint64_t nr;
    uint64_t time_enabled;
    uint64_t time_running;
    bts_read_value values[BTS_HPC_EVENT_COUNT];
} bts_group_read;

static int bts_fds[BTS_HPC_EVENT_COUNT] = {-1, -1};
static uint64_t bts_ids[BTS_HPC_EVENT_COUNT];
static bts_hpc_snapshot bts_snapshot;

static long bts_perf_event_open(
    struct perf_event_attr *attr,
    pid_t pid,
    int cpu,
    int group_fd,
    unsigned long flags)
{
    return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static void bts_close_all(void)
{
    unsigned int i;

    for (i = 0; i < BTS_HPC_EVENT_COUNT; ++i) {
        if (bts_fds[i] >= 0) {
            close(bts_fds[i]);
            bts_fds[i] = -1;
        }
        bts_ids[i] = 0;
    }
}

int bts_hpc_init(void)
{
    static const uint32_t types[BTS_HPC_EVENT_COUNT] = {
        PERF_TYPE_HARDWARE,
#if BTS_REGION == 1
        PERF_TYPE_HARDWARE,
#else
        BTS_PMU_TYPE,
#endif
    };
    static const uint64_t configs[BTS_HPC_EVENT_COUNT] = {
        PERF_COUNT_HW_CPU_CYCLES,
#if BTS_REGION == 1
        PERF_COUNT_HW_INSTRUCTIONS,
#else
        BTS_LOAD_CONFIG,
#endif
    };
    unsigned int i;
    int leader = -1;

    bts_close_all();
    memset(&bts_snapshot, 0, sizeof(bts_snapshot));

    for (i = 0; i < BTS_HPC_EVENT_COUNT; ++i) {
        struct perf_event_attr attr;
        int fd;

        memset(&attr, 0, sizeof(attr));
        attr.size = sizeof(attr);
        attr.type = types[i];
        attr.config = configs[i];
        attr.disabled = (i == 0);
        attr.exclude_kernel = 1;
        attr.exclude_hv = 1;
        attr.read_format =
            PERF_FORMAT_GROUP |
            PERF_FORMAT_ID |
            PERF_FORMAT_TOTAL_TIME_ENABLED |
            PERF_FORMAT_TOTAL_TIME_RUNNING;

        bts_snapshot.requested_mask |= UINT32_C(1) << i;
        fd = (int)bts_perf_event_open(
            &attr,
            0,
            -1,
            i == 0 ? -1 : leader,
            0);
        if (fd < 0) {
            int saved = errno;
            bts_close_all();
            bts_snapshot.error_code = -saved;
            return -saved;
        }
        if (ioctl(fd, PERF_EVENT_IOC_ID, &bts_ids[i]) != 0) {
            int saved = errno;
            close(fd);
            bts_close_all();
            bts_snapshot.error_code = -saved;
            return -saved;
        }

        bts_fds[i] = fd;
        bts_snapshot.available_mask |= UINT32_C(1) << i;
        if (i == 0) {
            leader = fd;
        }
    }

    return 0;
}

void bts_hpc_close(void)
{
    bts_close_all();
}

const char *bts_event_name(unsigned int index)
{
    static const char *const names[BTS_HPC_EVENT_COUNT] = {
        "cycles",
#if BTS_REGION == 1
        "instructions",
#else
        "retired_loads",
#endif
    };
    return index < BTS_HPC_EVENT_COUNT ? names[index] : "invalid";
}

void bts_get_hpc_snapshot(bts_hpc_snapshot *out)
{
    if (out != NULL) {
        *out = bts_snapshot;
    }
}

static inline void bts_barrier(void)
{
    __asm__ __volatile__("" ::: "memory");
}

static int bts_hpc_begin(void)
{
    bts_snapshot.time_enabled = 0;
    bts_snapshot.time_running = 0;
    bts_snapshot.values[0] = 0;
    bts_snapshot.values[1] = 0;
    bts_snapshot.valid_mask = 0;
    bts_snapshot.error_code = 0;

    bts_barrier();
    if (ioctl(
            bts_fds[0],
            PERF_EVENT_IOC_RESET,
            PERF_IOC_FLAG_GROUP) != 0) {
        return -errno;
    }
    if (ioctl(
            bts_fds[0],
            PERF_EVENT_IOC_ENABLE,
            PERF_IOC_FLAG_GROUP) != 0) {
        return -errno;
    }
    bts_barrier();
    return 0;
}

static int bts_hpc_end(void)
{
    bts_group_read data;
    ssize_t got;
    unsigned int i;
    unsigned int j;

    bts_barrier();
    if (ioctl(
            bts_fds[0],
            PERF_EVENT_IOC_DISABLE,
            PERF_IOC_FLAG_GROUP) != 0) {
        return -errno;
    }
    bts_barrier();

    memset(&data, 0, sizeof(data));
    got = read(bts_fds[0], &data, sizeof(data));
    if (got < (ssize_t)(3u * sizeof(uint64_t))) {
        return got < 0 ? -errno : -EIO;
    }

    bts_snapshot.time_enabled = data.time_enabled;
    bts_snapshot.time_running = data.time_running;

    if (data.nr > BTS_HPC_EVENT_COUNT) {
        data.nr = BTS_HPC_EVENT_COUNT;
    }
    for (i = 0; i < data.nr; ++i) {
        for (j = 0; j < BTS_HPC_EVENT_COUNT; ++j) {
            if (data.values[i].id == bts_ids[j]) {
                bts_snapshot.values[j] = data.values[i].value;
                bts_snapshot.valid_mask |= UINT32_C(1) << j;
                break;
            }
        }
    }

    return 0;
}

static const uint64_t bts_round_constants[24] = {
    UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
    UINT64_C(0x800000000000808a), UINT64_C(0x8000000080008000),
    UINT64_C(0x000000000000808b), UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
    UINT64_C(0x000000000000008a), UINT64_C(0x0000000000000088),
    UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000a),
    UINT64_C(0x000000008000808b), UINT64_C(0x800000000000008b),
    UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
    UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
    UINT64_C(0x000000000000800a), UINT64_C(0x800000008000000a),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
    UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008),
};

static const unsigned int bts_rotation[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
};

static const unsigned int bts_pilane[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
};

static inline uint64_t bts_rol64(uint64_t x, unsigned int shift)
{
    return (x << shift) | (x >> (64u - shift));
}

static void bts_keccakf1600(uint64_t state[25])
{
    uint64_t bc[5];
    uint64_t t;
    unsigned int round;
    unsigned int i;
    unsigned int j;

    for (round = 0; round < 24u; ++round) {
        for (i = 0; i < 5u; ++i) {
            bc[i] =
                state[i] ^
                state[i + 5u] ^
                state[i + 10u] ^
                state[i + 15u] ^
                state[i + 20u];
        }
        for (i = 0; i < 5u; ++i) {
            t =
                bc[(i + 4u) % 5u] ^
                bts_rol64(bc[(i + 1u) % 5u], 1u);
            for (j = 0; j < 25u; j += 5u) {
                state[j + i] ^= t;
            }
        }
        t = state[1];
        for (i = 0; i < 24u; ++i) {
            j = bts_pilane[i];
            bc[0] = state[j];
            state[j] = bts_rol64(t, bts_rotation[i]);
            t = bc[0];
        }
        for (j = 0; j < 25u; j += 5u) {
            for (i = 0; i < 5u; ++i) {
                bc[i] = state[j + i];
            }
            for (i = 0; i < 5u; ++i) {
                state[j + i] =
                    bc[i] ^
                    ((~bc[(i + 1u) % 5u]) &
                     bc[(i + 2u) % 5u]);
            }
        }
        state[0] ^= bts_round_constants[round];
    }
}

static uint64_t bts_load64(const uint8_t *src)
{
    uint64_t value = 0;
    unsigned int i;

    for (i = 0; i < 8u; ++i) {
        value |= (uint64_t)src[i] << (8u * i);
    }
    return value;
}

static void bts_store64(uint8_t *dst, uint64_t value)
{
    unsigned int i;

    for (i = 0; i < 8u; ++i) {
        dst[i] = (uint8_t)(value >> (8u * i));
    }
}

__attribute__((noinline, noclone, used))
void bts_absorb_full_block_entry(
    uint64_t state[25],
    const uint8_t block[BTS_SHAKE256_RATE])
{
    unsigned int i;

    for (i = 0; i < BTS_SHAKE256_RATE / 8u; ++i) {
        state[i] ^= bts_load64(block + 8u * i);
    }
    bts_keccakf1600(state);
}

__attribute__((noinline, noclone, used))
void bts_absorb_tail_entry(
    uint8_t output[BTS_SHAKE_OUTPUT_BYTES],
    uint64_t state[25],
    const uint8_t tail[BTS_SHAKE_TAIL_BYTES])
{
    uint8_t block[BTS_SHAKE256_RATE];
    unsigned int i;

    memset(block, 0, sizeof(block));
    memcpy(block, tail, BTS_SHAKE_TAIL_BYTES);
    block[BTS_SHAKE_TAIL_BYTES] ^= UINT8_C(0x1f);
    block[BTS_SHAKE256_RATE - 1u] ^= UINT8_C(0x80);

    for (i = 0; i < BTS_SHAKE256_RATE / 8u; ++i) {
        state[i] ^= bts_load64(block + 8u * i);
    }
    bts_keccakf1600(state);

    for (i = 0; i < BTS_SHAKE_OUTPUT_BYTES / 8u; ++i) {
        bts_store64(output + 8u * i, state[i]);
    }
}

void bts_reference_shake(
    uint8_t output[BTS_SHAKE_OUTPUT_BYTES],
    const uint8_t input[BTS_SHAKE_INPUT_BYTES],
    unsigned int full_blocks)
{
    uint64_t state[25] = {0};
    unsigned int block;

    for (block = 0; block < full_blocks; ++block) {
        bts_absorb_full_block_entry(
            state,
            input + block * BTS_SHAKE256_RATE);
    }

    bts_absorb_tail_entry(
        output,
        state,
        input + BTS_SHAKE_FULL_BLOCKS * BTS_SHAKE256_RATE);
}

int32_t bts_reference_polyz_coefficient(
    const uint8_t packed_group[BTS_POLYZ_GROUP_BYTES],
    int skipped_load)
{
    uint32_t loaded = 0;

    if (!skipped_load) {
        loaded =
            (uint32_t)packed_group[2] |
            ((uint32_t)packed_group[3] << 8) |
            ((uint32_t)packed_group[4] << 16) |
            ((uint32_t)packed_group[5] << 24);
    }

    loaded = (loaded >> 2) & UINT32_C(0x3ffff);
    return (int32_t)BTS_GAMMA1 - (int32_t)loaded;
}

__attribute__((noinline, noclone))
void bts_measure_target(bts_job *job)
{
    int rc;

#if BTS_REGION == 2
    /*
     * Establish the ARM-r5 analogue as zero before the PMU window.
     * r12 is callee-saved under SysV, so bts_hpc_begin preserves the value.
     */
    __asm__ __volatile__(
        "xorl %%r12d, %%r12d"
        :
        :
        : "r12", "cc");
#endif

    rc = bts_hpc_begin();
    if (rc != 0) {
        bts_snapshot.error_code = rc;
        return;
    }

    bts_target(job);

    rc = bts_hpc_end();
    bts_snapshot.error_code = rc;
}
