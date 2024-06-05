#!/usr/bin/env python
from pwn import *
from ctypes import CDLL
from ctypes.util import find_library

libc = CDLL(find_library("c"))
libc.srand(libc.time(0))

conn = remote('140.113.24.241', 30171)

secret = bytearray(16)
for i in range(16):
    secret[i] = 48 + (libc.rand() % (126 - 47) + 1)

conn.recvuntil(b'Please enter the secret:')
conn.sendline(secret)
#print(f'my secret :' , secret)

cor_response = conn.recvuntil(b'You got it! Here is your flag!')

while True:
    try:
        flag_response = conn.recvline()
        if not flag_response:
            break
        decoded_response = flag_response.decode().strip()
        if decoded_response.startswith("FLAG{"):
            print(decoded_response)
            break
    except EOFError:
        break

conn.close()