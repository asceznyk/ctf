.global _start
.intel_syntax noprefix
.section .text

_start:
    and rdi, 1
    xor rdi, 1
    xor rax, rax
    or rax, rdi
