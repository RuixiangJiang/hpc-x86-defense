
/*
 * Paper-exact x86-64 target primitives for Ravi et al.
 *
 * Each attack primitive is the corresponding baseline primitive with exactly
 * one instruction omitted.  Do not replace the omitted instruction by NOP.
 * System V AMD64 ABI:
 *   rdi = destination
 *   rsi = first/source pointer
 *   rdx = second source pointer, when present
 */

    .text

    .p2align 4
    .globl ravi_v1_baseline_asm
    .type ravi_v1_baseline_asm, @function
ravi_v1_baseline_asm:
    movl    (%rdi), %eax       /* destination initially contains c*s1 */
    movl    (%rsi), %edx       /* y */
    addl    %edx, %eax
    movl    %eax, (%rdi)       /* paper target: STR.W equivalent */
    ret
    .size ravi_v1_baseline_asm, .-ravi_v1_baseline_asm

    .p2align 4
    .globl ravi_v1_skip_store_asm
    .type ravi_v1_skip_store_asm, @function
ravi_v1_skip_store_asm:
    movl    (%rdi), %eax
    movl    (%rsi), %edx
    addl    %edx, %eax
                                /* skipped result store */
    ret
    .size ravi_v1_skip_store_asm, .-ravi_v1_skip_store_asm

    .p2align 4
    .globl ravi_v2_baseline_asm
    .type ravi_v2_baseline_asm, @function
ravi_v2_baseline_asm:
    movl    (%rdi), %eax       /* destination initially contains y */
    movl    (%rsi), %edx       /* saved c*s1 */
    addl    %edx, %eax
    movl    %eax, (%rdi)       /* paper target: STR.W equivalent */
    ret
    .size ravi_v2_baseline_asm, .-ravi_v2_baseline_asm

    .p2align 4
    .globl ravi_v2_skip_store_asm
    .type ravi_v2_skip_store_asm, @function
ravi_v2_skip_store_asm:
    movl    (%rdi), %eax
    movl    (%rsi), %edx
    addl    %edx, %eax
                                /* skipped result store */
    ret
    .size ravi_v2_skip_store_asm, .-ravi_v2_skip_store_asm

    .p2align 4
    .globl ravi_v3_baseline_asm
    .type ravi_v3_baseline_asm, @function
ravi_v3_baseline_asm:
    movl    (%rsi), %eax       /* saved c*s1; destination is separate */
    movl    (%rdx), %ecx       /* saved y */
    addl    %ecx, %eax         /* paper target: ADD equivalent */
    movl    %eax, (%rdi)
    ret
    .size ravi_v3_baseline_asm, .-ravi_v3_baseline_asm

    .p2align 4
    .globl ravi_v3_skip_add_asm
    .type ravi_v3_skip_add_asm, @function
ravi_v3_skip_add_asm:
    movl    (%rsi), %eax
    movl    (%rdx), %ecx
                                /* skipped ADD; eax still contains c*s1 */
    movl    %eax, (%rdi)
    ret
    .size ravi_v3_skip_add_asm, .-ravi_v3_skip_add_asm

    .section .note.GNU-stack,"",@progbits
