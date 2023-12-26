.global _start
.intel_syntax noprefix
.section .text

_start:
    mov rbp, 0x402000
    call mcb
    ret
mcb:
    mov rdx, 0
    mov rcx, 0
    mov rax, rsi
    sub rsi, 1
block1:
    cmp rcx, rsi
    jle block2
    jmp code1
block2:
    add rdi, rcx
    mov dl, byte ptr [rdi]
    sub rbp, rdx
    add byte ptr [rbp], 1
    add rbp, rdx
    sub rdi, rcx
    inc rcx
    jmp block1
code1:
    mov rdx, 0
    mov rcx, 0
    mov rax, 0
block3:
    cmp rdx, 0xff
    jle block4
    ret
block4:
    sub rbp, rdx
    cmp byte ptr [rbp], cl
    ja block5
    jmp outer
block5:
    mov cl, byte ptr [rbp]
    mov al, dl
outer:
    add rbp, rdx
    inc rdx
    jmp block3

