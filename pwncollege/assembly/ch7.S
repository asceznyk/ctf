.global _start
.intel_syntax

.section .text

_start:
    shl %rdi, 24
    shr %rdi, 56
    mov %eax, %edi
