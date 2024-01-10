.global _start
.intel_syntax noprefix
.section .text

_start:
    mov rax, [0x404000]
    mov rbx, [0x404000]
    add rbx, 0x1337
    mov [0x404000], rbx
