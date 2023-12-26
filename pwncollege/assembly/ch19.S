.global _start
.intel_syntax noprefix

.section .text

_start:
    cmp rdi, 3
    jbe case
    jmp [rsi+0x20]
case:
    jmp [rsi+rdi*0x8]

