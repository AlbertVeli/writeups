#!/usr/bin/env python2

# Only lowercase, add some code for uppercase too
def caesar_lower(s, shift):
    msg = ''
    for c in s:
        i = ord(c)
        if (i >= ord('a')) and (i <= ord('z')):
            i = (i - ord('a') + shift) % 26 + ord('a')
        msg += chr(i)
    return msg

s = 'yjhipvddsdasrpthpgrxewtgdqnjytto'
for i in range(1, 26):
    print i, caesar_lower(s, i)
