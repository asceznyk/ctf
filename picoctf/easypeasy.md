# Writeup - Easy Peasy
Category: Cryptography, Points: 40


## Descpriton

> A one-time pad is unbreakable, but can you manage to recover the flag? (Wrap with picoCTF{})

a netcat command is given and a python file is shared.


## Vulnerability

Given the source:

```python
#!/usr/bin/python3 -u
import os.path

KEY_FILE = "key"
KEY_LEN = 50000
FLAG_FILE = "flag"


def startup(key_location):
  flag = open(FLAG_FILE).read()
  kf = open(KEY_FILE, "rb").read()

  start = key_location
  stop = key_location + len(flag)

  key = kf[start:stop]
  key_location = stop

  result = list(map(lambda p, k: "{:02x}".format(ord(p) ^ k), flag, key))
  print("This is the encrypted flag!\n{}\n".format("".join(result)))

  return key_location

def encrypt(key_location):
  ui = input("What data would you like to encrypt? ").rstrip()
  if len(ui) == 0 or len(ui) > KEY_LEN:
    return -1

  start = key_location
  stop = key_location + len(ui)
  kf = open(KEY_FILE, "rb").read()

  if stop >= KEY_LEN:
    stop = stop % KEY_LEN
    key = kf[start:] + kf[:stop]
  else:
    key = kf[start:stop]
  key_location = stop

  result = list(map(lambda p, k: "{:02x}".format(ord(p) ^ k), ui, key))

  print("Here ya go!\n{}\n".format("".join(result)))

  return key_location


print("******************Welcome to our OTP implementation!******************")
c = startup(0)
while c >= 0:
  c = encrypt(c)
```

This code implements [One-time pad](https://en.wikipedia.org/wiki/One-time_pad) cipher.

Now, One-time pad cipher works like this:

```console
## here k is the key and m is the plaintext message and c is the ciphertext
## E is the encrytion function with k and m as args
## D is the decryption function with k and c as args
## the '^' symbol is bitwise XOR 
E(k, m) = k ^ m  = c 
D(k, c) = k ^ c = m 
```

How it works:
1. The first line is encrypting the plaintext `m` into ciphertext `c` by XORing `k` with `m`. 
2. The second line is decrypting from ciphertext `c` to plaintext `m` by XORing `k` with `c`.

This tells us that if we were to know the cipher `c`, we can decrypt it without knowing the key. 

When we execute `./otp.py`:

```console
$ ./otp.py 
******************Welcome to our OTP implementation!******************
This is the encrypted flag!
180117403c545546096a02050e5e566c09073a515555064b69

What data would you like to encrypt? 
```

We can see that the encrypted flag is `180117403c545546096a02050e5e566c09073a515555064b69`. Note that this flag is hexadecimal. We need to convert it to ascii to get the actual cipher. 

This is the actual cipher `enc = \x18\x01\x17@<TUF\tj\x02\x05\x0e^Vl\t\x07:QUU\x06Ki`.

If we input `enc` to the `encrypt` function we can get the hexadecimal `flag`.

For the decryption to work we have to make sure the same part of the `key` is XORed with the input. Which part of the `key` is used depends on the `key_location` variable.

The `key_location` was `0` when `key` was XORed with `flag`.

Hence, as long as the `key_location` is `0`. We can input `enc` to the `encrypt` function and get the hexadecimal for the `flag`, which we can then convert to plaintext.
 
How do we set the `key_location` to `0` programatically?

Notice these lines:

```python
  if stop >= KEY_LEN:
    stop = stop % KEY_LEN

  ## some lines here

  key_location = stop
```

If you notice the source code, when the variable `stop` is `>=` to the `KEY_LEN`, `stop = stop % KEY_LEN`. Since we know `KEY_LEN = 50000` if `stop = 50000`, then `stop = 50000 % 50000` which is `0`. If `stop = 0` then `key_location` will be set to `0` in the next line.

Hence, we need to give an input which is `50000 - len(enc)`, because the `key_location` would be at `len(enc)`. This would make `key_location = 0`. 


## Exploit

Now that we know how to make `key_location = 0` and call `encrypt` to decrypt `enc`. We need to do just that:
1. Run `./otp.py` to get the hexadecimal encrypted flag. Copy it. Then close.
2. Convert the hexadecimal into ascii as `enc` variable. Note the `len(enc)`.
3. Create a plaintext file with `50000 - len(enc)` random characters.
4. Run `./otp.py` again.
5. Input the plaintext file into when it asks you to decrypt something.
6. It will ask you to decrypt something again. Input the `enc` variable.

You should get your flag in hexadecimal which you will have to convert to ascii. 

Here is the full python exploit:

```python
import sys

from pwn import *

expline = "What data would you like to encrypt?"
io = process("./otp.py") if sys.argv[1] != "remote" else remote("mercury.picoctf.net", "36981")
io.recvline()
io.recvline()
dcipher = bytearray.fromhex(io.recvline().decode("utf-8")).decode()
exploit = "A"*(50000 - len(dcipher))
info(io.recvuntil(expline))
io.sendline(exploit)
info(io.recvuntil(expline))
io.sendline(dcipher)
info(io.recvline())
flag = io.recvline()
print(bytearray.fromhex(flag.decode("utf-8")).decode())
```

This does all of the steps above.

You should get the flag.
