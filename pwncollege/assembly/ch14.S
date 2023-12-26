.global _start
.intel_syntax

.section .text

_start:
    pop %rdx    
    sub %rdx, %rdi
    push %rdx

