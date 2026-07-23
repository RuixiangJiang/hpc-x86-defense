/*
 * x86-64 architectural analogue of the paper's skipped ARM Thumb MOVS.
 *
 * ARM MOVS writes a register and updates condition flags. x86 has no
 * instruction with exactly that mnemonic/semantics. Here:
 *
 *     xorl %r10d, %r10d     establishes stale ZF=1 and old value 0
 *     orl  $1, %r10d        baseline-only MOVS-equivalent effect:
 *                           destination becomes 1 and ZF becomes 0
 *     jnz  .Lsuffix         identical conditional branch in both builds
 *
 * In the attack build only ORL is absent. JNZ therefore reads stale ZF=1,
 * is not taken, and the Keccak loop aborts after round 7.
 */

#ifndef MFK_MOVS_SKIP_BUILD
#define MFK_MOVS_SKIP_BUILD 0
#endif

    .text
    .p2align 12
    .globl mfk_keccak_target
    .type mfk_keccak_target, @function
mfk_keccak_target:
    pushq %rbx
    movq %rdi, %rbx

    /* Prefix: rounds 0..7 execute in both builds. */
    movq %rbx, %rdi
    movl $0, %esi
    call mfk_keccak_round
    movq %rbx, %rdi
    movl $1, %esi
    call mfk_keccak_round
    movq %rbx, %rdi
    movl $2, %esi
    call mfk_keccak_round
    movq %rbx, %rdi
    movl $3, %esi
    call mfk_keccak_round
    movq %rbx, %rdi
    movl $4, %esi
    call mfk_keccak_round
    movq %rbx, %rdi
    movl $5, %esi
    call mfk_keccak_round
    movq %rbx, %rdi
    movl $6, %esi
    call mfk_keccak_round
    movq %rbx, %rdi
    movl $7, %esi
    call mfk_keccak_round

    /* Old destination = 0 and stale ZF = 1. */
    xorl %r10d, %r10d
#if MFK_MOVS_SKIP_BUILD == 0
.Lmfk_movs_equivalent:
    orl $1, %r10d
#endif
.Lmfk_loop_branch:
    jnz .Lmfk_suffix

    /* Attack path: branch not taken; normal epilogue follows. */
    popq %rbx
    ret

.Lmfk_suffix:
    /* Baseline path: rounds 8..23. */
    movq %rbx, %rdi
    movl $8, %esi
    call mfk_keccak_round
    movq %rbx, %rdi
    movl $9, %esi
    call mfk_keccak_round
    movq %rbx, %rdi
    movl $10, %esi
    call mfk_keccak_round
    movq %rbx, %rdi
    movl $11, %esi
    call mfk_keccak_round
    movq %rbx, %rdi
    movl $12, %esi
    call mfk_keccak_round
    movq %rbx, %rdi
    movl $13, %esi
    call mfk_keccak_round
    movq %rbx, %rdi
    movl $14, %esi
    call mfk_keccak_round
    movq %rbx, %rdi
    movl $15, %esi
    call mfk_keccak_round
    movq %rbx, %rdi
    movl $16, %esi
    call mfk_keccak_round
    movq %rbx, %rdi
    movl $17, %esi
    call mfk_keccak_round
    movq %rbx, %rdi
    movl $18, %esi
    call mfk_keccak_round
    movq %rbx, %rdi
    movl $19, %esi
    call mfk_keccak_round
    movq %rbx, %rdi
    movl $20, %esi
    call mfk_keccak_round
    movq %rbx, %rdi
    movl $21, %esi
    call mfk_keccak_round
    movq %rbx, %rdi
    movl $22, %esi
    call mfk_keccak_round
    movq %rbx, %rdi
    movl $23, %esi
    call mfk_keccak_round

    popq %rbx
    ret
    .size mfk_keccak_target, .-mfk_keccak_target

    .section .note.GNU-stack,"",@progbits
