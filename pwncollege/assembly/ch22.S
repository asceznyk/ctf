.global _start
.intel_syntax noprefix
.section .text

_start:
    mov rcx, 0
    call strlow
    mov rax, rcx
    ret
foo:
    mov rax, 0x20
    add rax, rdi
    ret
strlow:
    cmp rdi, 0
    jne block1
    ret
block1:
    cmp byte ptr [rdi], 0x00
    jne block2
    ret
block2:
    cmp byte ptr [rdi], 0x5a
    jle block3
    inc rdi
    jmp block1
block3:
    mov rdx, rdi
    mov dil, byte ptr [rdi]
    call foo
    mov rdi, rdx
    mov byte ptr [rdi], al
    inc rcx
    inc rdi
    jmp block1

