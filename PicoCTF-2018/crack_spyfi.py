#!/usr/bin/env python2

from pwn import *
from Crypto.Cipher import AES
import textwrap
import string

allchars = string.printable

def pad(message):
    if len(message) % 16 != 0:
        message = message + '0'*(16 - len(message)%16 )
    return message

def encrypt(key, plain):
    cipher = AES.new( key.decode('hex'), AES.MODE_ECB )
    return cipher.encrypt(plain).encode('hex')

def guess(g):
    sitrep = 'A'*11
    postlen = 41 - (len(g) - 8)
    post = 'C' * postlen
    crackline = 'B' * 16
    sitrep += crackline
    sitrep += post
    s_guess = 'ode is: ' + g
    s_last = s_guess[-16:]
    sitrep = sitrep.replace(crackline, s_last)

    print "DBG:", sitrep

    p = process('./spy_terminal_fake_flag.py')
    #p = remote('2018shell2.picoctf.com', 30399)
    p.recvuntil('enter your situation report: ')
    p.sendline(sitrep)

    c = p.recvall()
    p.close()
    cc = textwrap.fill(c, 32).split()
    print cc
    if cc[4] == cc[9]:
        return True
    return False

start_guess = 'picoCTF{'
while True:
    for c in allchars:
        g = start_guess + c
        if guess(g):
            start_guess = g
            print ''
            print g
            print ''
            if g[-1] == '}':
                exit(0)
            break
