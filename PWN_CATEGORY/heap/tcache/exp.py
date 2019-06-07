# File: exp.py
# Author: raycp
# Date: 2019-06-02
# Description: exp for ...

from pwn_debug import *


pdbg=pwn_debug("level2")

pdbg.context.terminal=['tmux', 'splitw', '-h']

pdbg.local()
#pdbg.debug("2.24")
#pdbg.remote('127.0.0.1', 22)
p=pdbg.run("local")
#p=pdbg.run("remote")
#p=pdbg.run("debug")

membp=pdbg.membp
#print hex(membp.elf_base),hex(membp.libc_base)
elf=pdbg.elf
libc=pdbg.libc

#io_file=IO_FILE_plus()
#io_file.show()

def pwn():
    
    #pdbg.bp()
    
    p.interactive() 

if __name__ == '__main__':
   pwn()


