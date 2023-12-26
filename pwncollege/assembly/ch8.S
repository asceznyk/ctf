.global _start
.intel_syntax

.section .text

_start:
    and %rdi, %rsi
    xor %rax, %rax
    add %rax, %rdi
