.global _start
.intel_syntax

.section .text

_start:
    add %rax, [%rsp+24]
    add %rax, [%rsp+16]
    add %rax, [%rsp+8]
    add %rax, [%rsp]
    mov %rbx, 4
    div %rbx 
    push %rax  
     
