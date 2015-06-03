#!/usr/bin/python

from pwn import *
import os, signal
context.log_level = 10000

# Making sure the gadgets in the poc are cached, so that
# we do not have to give an unnecessarily high timeout
# below.
r = ROP("poc-32")

with tempfile.NamedTemporaryFile() as fd:
    s = randoms(12)+"\n"
    fd.write(s)
    fd.flush()

    try:
        p = process(["python", "doit.py"])

        p.sendline("cat " + fd.name)
        flag = p.recvline(timeout=5)
        if b64e(flag) == b64e(s):
            print "ok"
        else:
            print "not ok"
    finally:
        p.close()
