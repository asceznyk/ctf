import sys

from pwn import *


r = remote('saturn.picoctf.net', sys.argv[1])
r.recv()
r.send("w")
x = r.recv()

print(x)


