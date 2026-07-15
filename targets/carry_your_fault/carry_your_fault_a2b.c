#include "carry_your_fault_a2b.h"

#include <stddef.h>
#include <stdint.h>

/* 16-bit, k=8, n=2 single-lookup A2B construction used by mkm4. */
enum {
    CYF_K = 8,
    CYF_N = 2,
    CYF_LOW_MASK = 0xff,
    CYF_WORD_MASK = 0xffff,
    CYF_TABLE_ENTRIES = CYF_N * (1 << (CYF_K + 1))
};

typedef struct {
    uint16_t table[CYF_TABLE_ENTRIES];
    uint8_t rho;
    uint16_t rrr;
    int initialized;
} cyf_a2b_context;

static cyf_a2b_context g_ctx;

static size_t table_index(size_t i, uint32_t beta, uint32_t value)
{
    return (i << (1u + CYF_K)) | (beta << CYF_K) | value;
}

void cyf_a2b_init(uint32_t seed)
{
    uint8_t r[CYF_N];
    size_t i;
    uint32_t value;

    g_ctx.rho = (uint8_t)(seed & 1u);
    r[0] = (uint8_t)((seed >> 8) & 0xffu);
    r[1] = (uint8_t)((seed >> 16) & 0xffu);
    g_ctx.rrr = (uint16_t)((uint16_t)r[0] |
                           ((uint16_t)r[1] << CYF_K));

    for (i = 0; i < CYF_N; ++i) {
        for (value = 0; value < (1u << CYF_K); ++value) {
            g_ctx.table[table_index(i, g_ctx.rho, value)] =
                (uint16_t)((value + r[i]) ^
                           (((uint32_t)g_ctx.rho << CYF_K) | r[i]));
            g_ctx.table[
                table_index(i, (uint32_t)(g_ctx.rho ^ 1u), value)
            ] = (uint16_t)((value + r[i] + 1u) ^
                           (((uint32_t)g_ctx.rho << CYF_K) | r[i]));
        }
    }

    g_ctx.initialized = 1;
}

__attribute__((noinline, noclone, aligned(4096)))
uint16_t cyf_a2b_target(uint16_t arithmetic_share,
                        uint16_t second_arithmetic_share)
{
    size_t i;
    uint32_t A = arithmetic_share;
    uint32_t R = second_arithmetic_share;
    uint32_t A_l;
    uint32_t R_l;
    uint32_t betaBi;
    uint32_t beta = g_ctx.rho;
    uint32_t Bi;
    uint32_t B = 0;

    A = (A - g_ctx.rrr) & CYF_WORD_MASK;

    for (i = 0; i < CYF_N; ++i) {
        R_l = R & CYF_LOW_MASK;
        A = (A + R_l) & ((1u << ((CYF_N - i) * CYF_K)) - 1u);
        A_l = A & CYF_LOW_MASK;

        betaBi = g_ctx.table[table_index(i, beta, A_l)];
        Bi = betaBi & CYF_LOW_MASK;
        beta = betaBi >> CYF_K;

        Bi ^= R_l;
        B |= Bi << (i * CYF_K);

        A >>= CYF_K;
        R >>= CYF_K;
    }

    return (uint16_t)(B ^ g_ctx.rrr);
}

/* First-order secure AND, equivalent to mkm4 secand for MASKING_N=2. */
static inline void secand_first_order(
    uint32_t x0,
    uint32_t x1,
    uint32_t y0,
    uint32_t y1,
    uint32_t random_mask,
    uint32_t *z0,
    uint32_t *z1)
{
    uint32_t left = x0 & y0;
    uint32_t right = x1 & y1;
    uint32_t cross =
        random_mask ^ (x0 & y1) ^ (x1 & y0);

    *z0 = left ^ random_mask;
    *z1 = right ^ cross;
}

__attribute__((noinline, noclone, aligned(4096)))
void cyf_post_fault_target(
    uint16_t boolean_share0,
    uint16_t boolean_share1,
    uint32_t w_prefix_share0,
    uint32_t w_prefix_share1,
    uint32_t x_prefix_share0,
    uint32_t x_prefix_share1,
    uint32_t x_bit_share0,
    uint32_t x_bit_share1,
    uint32_t r_share0,
    uint32_t r_share1,
    uint32_t secand_mask0,
    uint32_t secand_mask1,
    cyf_post_result *out)
{
    uint32_t w0;
    uint32_t w1;
    uint32_t x0;
    uint32_t x1;
    uint32_t t0;
    uint32_t t1;
    uint32_t q0;
    uint32_t q1;
    uint32_t res;

    /* mkm4 polycompare post-A2B bit packing. */
    w0 = (w_prefix_share0 << 1) |
         (((uint32_t)boolean_share0 >> CYF_TARGET_BIT) & 1u);
    w1 = (w_prefix_share1 << 1) |
         (((uint32_t)boolean_share1 >> CYF_TARGET_BIT) & 1u);

    x0 = (x_prefix_share0 << 1) | (x_bit_share0 & 1u);
    x1 = (x_prefix_share1 << 1) | (x_bit_share1 & 1u);

    /* r = secand(r, secand(w, x)). */
    secand_first_order(
        w0, w1, x0, x1, secand_mask0, &t0, &t1);
    secand_first_order(
        r_share0, r_share1, t0, t1, secand_mask1, &q0, &q1);

    res = q0 ^ q1;

    out->packed_w_share0 = w0;
    out->packed_w_share1 = w1;
    out->packed_x_share0 = x0;
    out->packed_x_share1 = x1;
    out->compare_share0 = q0;
    out->compare_share1 = q1;
    out->unmasked_w = w0 ^ w1;
    out->unmasked_x = x0 ^ x1;
    out->unmasked_compare = res;

    /* mkm4 compresses all 32 equality bits into one result bit. */
    res &= res >> 16;
    res &= res >> 8;
    res &= res >> 4;
    res &= res >> 2;
    res &= res >> 1;
    out->comparison_failure = (uint8_t)!(res & 1u);
}

uint16_t cyf_recombine_arithmetic(uint16_t a, uint16_t r)
{
    return (uint16_t)(a + r);
}
