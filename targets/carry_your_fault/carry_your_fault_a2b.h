#ifndef CARRY_YOUR_FAULT_A2B_H
#define CARRY_YOUR_FAULT_A2B_H

#include <stdint.h>

#define CYF_A2B_WORD_BITS 16u
#define CYF_TARGET_BIT 11u
#define CYF_TARGET_MASK (UINT16_C(1) << CYF_TARGET_BIT)
#define CYF_POST_PREFIX_BITS 31u
#define CYF_POST_PREFIX_MASK UINT32_C(0x7fffffff)

typedef struct {
    uint32_t packed_w_share0;
    uint32_t packed_w_share1;
    uint32_t packed_x_share0;
    uint32_t packed_x_share1;
    uint32_t compare_share0;
    uint32_t compare_share1;
    uint32_t unmasked_w;
    uint32_t unmasked_x;
    uint32_t unmasked_compare;
    uint8_t comparison_failure;
} cyf_post_result;

/* Initialize the A2B lookup table outside every PMU interval. */
void cyf_a2b_init(uint32_t seed);

/*
 * Original first-order single-lookup A2B consumer from masked Kyber.
 * Baseline and attack binaries execute the same compiled function.
 */
__attribute__((noinline, noclone))
uint16_t cyf_a2b_target(uint16_t arithmetic_share,
                        uint16_t second_arithmetic_share);

/*
 * Faithful post-A2B propagation target based on mkm4 polycompare:
 *
 *   w[n] <<= 1;
 *   w[n] |= (a2b_share[n] >> 11) & 1;
 *   r = secand(r, secand(w, x));
 *   unmask and compress the result to one equality/failure bit.
 *
 * All randomness and masked prefixes are supplied by the caller and are
 * prepared before PMU enable.  No attack flag, fault assignment, or
 * attack-dependent branch is present in this function.
 */
__attribute__((noinline, noclone))
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
    cyf_post_result *out);

uint16_t cyf_recombine_arithmetic(uint16_t a, uint16_t r);

#endif
