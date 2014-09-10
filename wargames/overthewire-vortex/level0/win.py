#!/usr/bin/env python2

from pwn import *

r = remote('vortex.labs.overthewire.org', 5842)
ns  = [r.recvn(4) for _ in range(4)]
res = sum(u32(n) for n in ns)
r.send(p32(res & 0xffffffff))

data = r.recvall()

creds = re.findall('Username: (.*) Password: (.*)', data)
assert len(creds) == 1

print creds[0][1]
