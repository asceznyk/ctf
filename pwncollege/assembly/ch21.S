.global _start
.intel_syntax noprefix
.section .text

_start:
    mov rax, 0
    cmp rdi, 0
    je end
op:
    cmp qword ptr [rdi], 0
    je end
    inc rax
    inc rdi
    jmp op
end:
    nop

