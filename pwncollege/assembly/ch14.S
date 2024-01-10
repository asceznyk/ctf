.global _start
.intel_syntax noprefix
.section .text

_start:
    pop rdx    
    sub rdx, rdi
    push rdx

