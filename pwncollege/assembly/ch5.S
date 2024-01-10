.global _start
.intel_syntax noprefix
.section .text

_start:
    mov eax, edi
    mov ebx, esi
    div ebx
    mov eax, edx
    
