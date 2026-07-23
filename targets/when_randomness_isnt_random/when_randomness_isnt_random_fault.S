/*
 * Instruction-level x86-64 analogues for the three ARM fault effects in
 * Valsaraj et al., "When Randomness Isn't Random".
 *
 * WRIR_REGION=1:
 *   baseline contains exactly one ADD that initializes noiseseed = base + 32.
 *   attack omits exactly that ADD, leaving noiseseed = base.
 *
 * WRIR_REGION=2:
 *   first instruction is the LDR analogue that loads the coins pointer from a
 *   synthetic stack frame. Baseline loads frame.correct (offset 0); attack
 *   loads frame.fault (offset 8). Both execute the same number of instructions.
 *
 * WRIR_REGION=3:
 *   same LDR-disturbance model for sigma initialization. Baseline loads the
 *   correct sigma pointer; attack loads a constant-filled wrong pointer.
 */

#ifndef WRIR_REGION
#define WRIR_REGION 1
#endif

#ifndef WRIR_ATTACK
#define WRIR_ATTACK 0
#endif

    .text
    .p2align 6
    .globl wrir_target
    .type wrir_target, @function
wrir_target:
#if WRIR_REGION == 1
    /* input=%rdi is seed-material base; output=%rsi stores noiseseed pointer. */
    movq %rdi, %rax
#if WRIR_ATTACK == 0
.Lwrir_target_add:
    addq $32, %rax
#endif
    movq %rax, (%rsi)
    ret

#elif WRIR_REGION == 2
    /*
     * input=%rdi points to wrir_pointer_frame on the caller's stack.
     * This MOV is the x86 LDR analogue under fault.
     */
#if WRIR_ATTACK == 0
.Lwrir_target_ldr:
    movq 0(%rdi), %rax
#else
.Lwrir_target_ldr:
    movq 8(%rdi), %rax
#endif
    movdqu 0(%rax), %xmm0
    movdqu 16(%rax), %xmm1
    movdqu %xmm0, 0(%rsi)
    movdqu %xmm1, 16(%rsi)
    ret

#elif WRIR_REGION == 3
    /*
     * input=%rdi points to wrir_pointer_frame on the caller's stack.
     * This MOV is the x86 LDR analogue under fault.
     */
#if WRIR_ATTACK == 0
.Lwrir_target_ldr:
    movq 0(%rdi), %rax
#else
.Lwrir_target_ldr:
    movq 8(%rdi), %rax
#endif
    movdqu 0(%rax), %xmm0
    movdqu 16(%rax), %xmm1
    movdqu 32(%rax), %xmm2
    movdqu 48(%rax), %xmm3
    movdqu %xmm0, 0(%rsi)
    movdqu %xmm1, 16(%rsi)
    movdqu %xmm2, 32(%rsi)
    movdqu %xmm3, 48(%rsi)
    ret
#else
#error "WRIR_REGION must be 1, 2, or 3"
#endif
    .size wrir_target, .-wrir_target
    .section .note.GNU-stack,"",@progbits
