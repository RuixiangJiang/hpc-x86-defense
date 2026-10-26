
/home/ruixiang/hpc-x86-defense/build/bin/ravi_fiddling_twiddle/fiddling_twiddle_single:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .plt.got:

Disassembly of section .plt.sec:

Disassembly of section .text:

0000000000006040 <PQCLEAN_DILITHIUM2_CLEAN_fiddle_target_group_corrupt_pointer>:
    6040:	f3 0f 1e fa          	endbr64
    6044:	55                   	push   %rbp
    6045:	89 f0                	mov    %esi,%eax
    6047:	48 89 e5             	mov    %rsp,%rbp
    604a:	41 57                	push   %r15
    604c:	41 56                	push   %r14
    604e:	41 55                	push   %r13
    6050:	41 54                	push   %r12
    6052:	53                   	push   %rbx
    6053:	48 83 ec 18          	sub    $0x18,%rsp

0000000000006057 <fiddle_twiddle_corrupt_pointer_load_site>:
    6057:	44 8b 2a             	mov    (%rdx),%r13d
    605a:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
    605e:	85 c0                	test   %eax,%eax
    6060:	74 39                	je     609b <fiddle_twiddle_corrupt_pointer_load_site+0x44>
    6062:	49 89 ff             	mov    %rdi,%r15
    6065:	49 89 c4             	mov    %rax,%r12
    6068:	4d 63 ed             	movslq %r13d,%r13
    606b:	31 db                	xor    %ebx,%ebx
    606d:	0f 1f 00             	nopl   (%rax)
    6070:	41 8d 04 1c          	lea    (%r12,%rbx,1),%eax
    6074:	4d 8d 34 87          	lea    (%r15,%rax,4),%r14
    6078:	49 63 3e             	movslq (%r14),%rdi
    607b:	49 0f af fd          	imul   %r13,%rdi
    607f:	e8 dc e7 ff ff       	call   4860 <PQCLEAN_DILITHIUM2_CLEAN_montgomery_reduce>
    6084:	41 8b 14 9f          	mov    (%r15,%rbx,4),%edx
    6088:	29 c2                	sub    %eax,%edx
    608a:	41 89 16             	mov    %edx,(%r14)
    608d:	41 01 04 9f          	add    %eax,(%r15,%rbx,4)
    6091:	48 83 c3 01          	add    $0x1,%rbx
    6095:	48 39 5d c8          	cmp    %rbx,-0x38(%rbp)
    6099:	75 d5                	jne    6070 <fiddle_twiddle_corrupt_pointer_load_site+0x19>
    609b:	48 83 c4 18          	add    $0x18,%rsp
    609f:	5b                   	pop    %rbx
    60a0:	41 5c                	pop    %r12
    60a2:	41 5d                	pop    %r13
    60a4:	41 5e                	pop    %r14
    60a6:	41 5f                	pop    %r15
    60a8:	5d                   	pop    %rbp
    60a9:	c3                   	ret

Disassembly of section .fini:
