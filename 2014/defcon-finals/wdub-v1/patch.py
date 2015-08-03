from pwn import *

#
# This patch changes a BLS (unsigned compare) to BLE (signed compare),
# which should avoid the overflow.
#
context.arch = 'thumb'
elf = ELF('./wdub')
elf.write(0xaa18, '\x04\xdd')
elf.save('./wdub-patch')
