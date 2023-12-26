.global _start
.intel_syntax noprefix

.section .text

_start:
    mov ebx, [edi]
    cmp ebx, 0x7f454c46
    jne first_try
    mov eax, [edi+4]
    add eax, [edi+8]
    add eax, [edi+12]
    jmp end
first_try:
    mov ebx, [edi]
    cmp bx, 0x5a4d
    jne second_try
    mov eax, [edi+4]
    sub eax, [edi+8]
    sub eax, [edi+12]
    jmp end
second_try:
    mov eax, [edi+4]
    imul eax, [edi+8]
    imul eax, [edi+12]
    jmp end
end:
    nop


