#!/usr/bin/env python

from pwn import *
import os, signal
context.log_level = 1000

with tempfile.NamedTemporaryFile() as fd:
    s = randoms(12)+"\n"
    fd.write(s)
    fd.flush()
    try:
        p = process(["python", "doit.py", "FLAG=%s"%fd.name])
        #p.sendline(fd.name)
        flagenc = p.recvline(timeout=5).strip()
        if flagenc == b64e(s):
            print "ok"
        else:
            print "not ok"
    finally:
        p.close()
