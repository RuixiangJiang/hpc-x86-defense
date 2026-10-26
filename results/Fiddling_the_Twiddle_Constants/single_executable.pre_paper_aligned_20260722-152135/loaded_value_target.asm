
/home/ruixiang/hpc-x86-defense/build/bin/ravi_fiddling_twiddle/fiddling_twiddle_single:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .plt.got:

Disassembly of section .plt.sec:

Disassembly of section .text:

0000000000006170 <PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_corrupt_loaded_value>:
    6170:	f3 0f 1e fa          	endbr64
    6174:	55                   	push   %rbp
    6175:	89 f0                	mov    %esi,%eax
    6177:	48 89 e5             	mov    %rsp,%rbp
    617a:	41 57                	push   %r15
    617c:	41 56                	push   %r14
    617e:	41 55                	push   %r13
    6180:	41 54                	push   %r12
    6182:	53                   	push   %rbx
    6183:	48 83 ec 18          	sub    $0x18,%rsp

0000000000006187 <fiddle_twiddle_corrupt_loaded_value_site>:
    6187:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    618b:	85 c0                	test   %eax,%eax
    618d:	74 3d                	je     61cc <fiddle_twiddle_corrupt_loaded_value_site+0x45>
    618f:	49 89 ff             	mov    %rdi,%r15
    6192:	49 89 c5             	mov    %rax,%r13
    6195:	4c 63 e2             	movslq %edx,%r12
    6198:	31 db                	xor    %ebx,%ebx
    619a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    61a0:	41 8d 44 1d 00       	lea    0x0(%r13,%rbx,1),%eax
    61a5:	4d 8d 34 87          	lea    (%r15,%rax,4),%r14
    61a9:	49 63 3e             	movslq (%r14),%rdi
    61ac:	49 0f af fc          	imul   %r12,%rdi
    61b0:	e8 ab e6 ff ff       	call   4860 <PQCLEAN_DILITHIUM2_CLEAN_montgomery_reduce>
    61b5:	41 8b 14 9f          	mov    (%r15,%rbx,4),%edx
    61b9:	29 c2                	sub    %eax,%edx
    61bb:	41 89 16             	mov    %edx,(%r14)
    61be:	41 01 04 9f          	add    %eax,(%r15,%rbx,4)
    61c2:	48 83 c3 01          	add    $0x1,%rbx
    61c6:	48 39 5d c8          	cmp    %rbx,-0x38(%rbp)
    61ca:	75 d4                	jne    61a0 <fiddle_twiddle_corrupt_loaded_value_site+0x19>
    61cc:	48 83 c4 18          	add    $0x18,%rsp
    61d0:	5b                   	pop    %rbx
    61d1:	41 5c                	pop    %r12
    61d3:	41 5d                	pop    %r13
    61d5:	41 5e                	pop    %r14
    61d7:	41 5f                	pop    %r15
    61d9:	5d                   	pop    %rbp
    61da:	c3                   	ret

Disassembly of section .fini:
