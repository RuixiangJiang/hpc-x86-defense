
/home/ruixiang/hpc-x86-defense/build/bin/ravi_fiddling_twiddle/fiddling_twiddle_single:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .plt.got:

Disassembly of section .plt.sec:

Disassembly of section .text:

0000000000005f10 <PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_baseline>:
    5f10:	f3 0f 1e fa          	endbr64
    5f14:	55                   	push   %rbp
    5f15:	89 f0                	mov    %esi,%eax
    5f17:	48 89 e5             	mov    %rsp,%rbp
    5f1a:	41 57                	push   %r15
    5f1c:	41 56                	push   %r14
    5f1e:	41 55                	push   %r13
    5f20:	41 54                	push   %r12
    5f22:	53                   	push   %rbx
    5f23:	48 83 ec 18          	sub    $0x18,%rsp

0000000000005f27 <fiddle_twiddle_original_load_site>:
    5f27:	44 8b 2a             	mov    (%rdx),%r13d
    5f2a:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    5f2e:	85 c0                	test   %eax,%eax
    5f30:	74 39                	je     5f6b <fiddle_twiddle_original_load_site+0x44>
    5f32:	49 89 ff             	mov    %rdi,%r15
    5f35:	49 89 c4             	mov    %rax,%r12
    5f38:	4d 63 ed             	movslq %r13d,%r13
    5f3b:	31 db                	xor    %ebx,%ebx
    5f3d:	0f 1f 00             	nopl   (%rax)
    5f40:	41 8d 04 1c          	lea    (%r12,%rbx,1),%eax
    5f44:	4d 8d 34 87          	lea    (%r15,%rax,4),%r14
    5f48:	49 63 3e             	movslq (%r14),%rdi
    5f4b:	49 0f af fd          	imul   %r13,%rdi
    5f4f:	e8 0c e9 ff ff       	call   4860 <PQCLEAN_DILITHIUM2_CLEAN_montgomery_reduce>
    5f54:	41 8b 14 9f          	mov    (%r15,%rbx,4),%edx
    5f58:	29 c2                	sub    %eax,%edx
    5f5a:	41 89 16             	mov    %edx,(%r14)
    5f5d:	41 01 04 9f          	add    %eax,(%r15,%rbx,4)
    5f61:	48 83 c3 01          	add    $0x1,%rbx
    5f65:	48 39 5d c8          	cmp    %rbx,-0x38(%rbp)
    5f69:	75 d5                	jne    5f40 <fiddle_twiddle_original_load_site+0x19>
    5f6b:	48 83 c4 18          	add    $0x18,%rsp
    5f6f:	5b                   	pop    %rbx
    5f70:	41 5c                	pop    %r12
    5f72:	41 5d                	pop    %r13
    5f74:	41 5e                	pop    %r14
    5f76:	41 5f                	pop    %r15
    5f78:	5d                   	pop    %rbp
    5f79:	c3                   	ret

Disassembly of section .fini:
