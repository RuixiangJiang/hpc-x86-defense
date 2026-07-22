.text

/*
 * Paper-aligned x86-64 analogue of ARM:
 *
 *     uadd16 a, a, b
 *
 * x86-64 has no scalar UADD16 instruction. PADdW is the corresponding
 * packed-halfword operation. Only the low 16-bit lane is consumed by the
 * current Kyber experiment.
 *
 * Baseline and attack are identical except that the attack omits PADdW.
 */

.p2align 4
.globl rou_target_uadd16_baseline
.type rou_target_uadd16_baseline,@function
rou_target_uadd16_baseline:
    movd    %edi, %xmm0
    movd    %esi, %xmm1
    paddw   %xmm1, %xmm0
    movd    %xmm0, %eax
    movswl  %ax, %eax
    ret
.size rou_target_uadd16_baseline, .-rou_target_uadd16_baseline

.p2align 4
.globl rou_target_skip_local_masked_operation
.type rou_target_skip_local_masked_operation,@function
rou_target_skip_local_masked_operation:
    movd    %edi, %xmm0
    movd    %esi, %xmm1
    /* PADdW/UADD16-equivalent instruction omitted */
    movd    %xmm0, %eax
    movswl  %ax, %eax
    ret
.size rou_target_skip_local_masked_operation, .-rou_target_skip_local_masked_operation

/*
 * Baseline and attack both call this same data consumer. The caller prepares
 * either the normal or bit-flipped intermediate before the PMU window.
 */
.p2align 4
.globl rou_target_flip_masked_intermediate_bit
.type rou_target_flip_masked_intermediate_bit,@function
rou_target_flip_masked_intermediate_bit:
    movl    %edx, %eax
    ret
.size rou_target_flip_masked_intermediate_bit, .-rou_target_flip_masked_intermediate_bit

.section .note.GNU-stack,"",@progbits
