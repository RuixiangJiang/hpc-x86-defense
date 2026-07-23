/*
 * x86-64 architectural analogues of the two ARM instruction-skip faults from
 * Du et al., "Breaking the Shield".
 *
 * Region 1:
 *   ARM target: BNE.N loop-back branch in SHAKE256 absorb.
 *   x86 target: JNZ loop-back branch after the fourth absorbed full block.
 *   Baseline executes the branch and absorbs all eight blocks.
 *   Attack omits exactly this JNZ and falls through after four blocks.
 *
 * Region 2:
 *   ARM target: LDR.W loading packed y data into r5.
 *   x86 target: MOVL 2(%rax), %r12d.
 *   The measurement wrapper establishes %r12d=0 before PMU enable.
 *   Baseline overwrites it with the packed word; attack omits exactly the
 *   MOVL, so the register remains zero for all dependent instructions.
 */

#ifndef BTS_REGION
#define BTS_REGION 1
#endif

#ifndef BTS_ATTACK
#define BTS_ATTACK 0
#endif

    .text
    .p2align 6
    .globl bts_target
    .type bts_target, @function
bts_target:
#if BTS_REGION == 1
    /*
     * bts_job:
     *   0(%rdi): input pointer
     *   8(%rdi): output pointer
     *
     * Prefix blocks 0,1,2 are explicit. The loop body begins at block 3.
     * Skipping its BNE/JNZ after the first iteration aborts after four blocks.
     */
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    subq $200, %rsp

    movq %rdi, %rbx
    movq %rsp, %r12

    /* Zero the 25-lane Keccak state. */
    xorl %eax, %eax
    movl $25, %ecx
    movq %r12, %rdi
    rep stosq

    movq 0(%rbx), %r13

    /* Full block 0. */
    movq %r12, %rdi
    movq %r13, %rsi
    call bts_absorb_full_block_entry
    addq $136, %r13

    /* Full block 1. */
    movq %r12, %rdi
    movq %r13, %rsi
    call bts_absorb_full_block_entry
    addq $136, %r13

    /* Full block 2. */
    movq %r12, %rdi
    movq %r13, %rsi
    call bts_absorb_full_block_entry
    addq $136, %r13

    /*
     * Blocks 3..7.
     * The first execution processes block 3. The branch below is the one
     * instruction omitted in the attack build.
     */
    movl $5, %r14d
.Lbts_absorb_loop_body:
    movq %r12, %rdi
    movq %r13, %rsi
    call bts_absorb_full_block_entry
    addq $136, %r13
    decl %r14d
#if BTS_ATTACK == 0
.Lbts_target_bne:
    jnz .Lbts_absorb_loop_body
#endif

    /*
     * Continue through the same post-loop tail handling. The tail address is
     * the canonical fixed tail following all eight full input blocks.
     */
    movq 8(%rbx), %rdi
    movq %r12, %rsi
    movq 0(%rbx), %rdx
    addq $1088, %rdx
    call bts_absorb_tail_entry

    addq $200, %rsp
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    ret

#elif BTS_REGION == 2
    /*
     * Reconstruct the second 18-bit coefficient in one 9-byte polyz group.
     *
     * packed bits:
     *   t1 = (load32(a+2) >> 2) & 0x3ffff
     *   y  = GAMMA1 - t1
     *
     * %r12d is established as zero before PMU enable.
     */
    movq 0(%rdi), %rax
    movq 8(%rdi), %rdx
#if BTS_ATTACK == 0
.Lbts_target_ldr:
    movl 2(%rax), %r12d
#endif
    shrl $2, %r12d
    andl $0x3ffff, %r12d
    movl $131072, %eax
    subl %r12d, %eax
    movl %eax, 0(%rdx)
    ret
#else
#error "BTS_REGION must be 1 or 2"
#endif
    .size bts_target, .-bts_target
    .section .note.GNU-stack,"",@progbits
