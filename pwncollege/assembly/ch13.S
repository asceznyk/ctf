.global _start
.intel_syntax noprefix
.section .text

_start:
    mov rax, [rdi]
    mov rbx, [rdi+8]
    add rax, rbx
    mov [rsi], rax
