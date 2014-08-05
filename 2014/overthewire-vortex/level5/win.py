#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

level    = 5
host     = 'vortex.labs.overthewire.org'
user     = 'vortex%i' % level
chal     = 'vortex%i' % level
password  = '<removed>'
passfile = '/etc/vortex_pass/vortex%i' % (level+1)
binary   = '/vortex/%s' % chal
shell    = ssh(host=host, user=user, password=password)


sh = shell.run(binary)
sh.sendline('rlTf6')

sh.sendline('id')
log.success('id: ' + sh.recvline().strip())

sh.sendline('cat %s' % passfile)
log.success('password: ' + sh.recvline().strip())
