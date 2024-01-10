.global _start
.intel_syntax noprefix
.section .text

_start:
    imul rdi, rsi
    add rdi, rdx
    mov rax, rdi
