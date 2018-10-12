#!/usr/bin/env python2

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
for x in range(width/4):
    r, g, b = pix[x, y]
    add_bit(r)
    add_bit(g)
    add_bit(b)

print msg
