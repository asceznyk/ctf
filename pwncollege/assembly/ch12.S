.global _start
.intel_syntax

.section .text

_start:
    mov %rax, 0xdeadbeef00001337
    mov [%rdi], %rax
    xor %rax, %rax
    mov %rbx, 0xc0ffee0000
    mov [%rsi], %rbx
    xor %rbx, %rbx
