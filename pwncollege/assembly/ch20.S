.global _start
.intel_syntax noprefix
.section .text

_start:
    mov rax, 0
    mov rbx, 0
loop:
    add rax, [rdi+rbx*8]
    inc rbx
    cmp rbx, rsi
    jb loop
end:
    div rbx

