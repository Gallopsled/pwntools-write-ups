#!/usr/bin/env python2

from pwn import *
context.log_level = 1000

with tempfile.NamedTemporaryFile() as fd:
    s = randoms(12)
    fd.write(s)
    fd.flush()

    p = process(["./doit.py", "SILENT"])
    p.sendline("base64 " + fd.name)
    p.shutdown("send")
    if p.recvall().strip() == b64e(s):
        print "ok"
    else:
        print "not ok"
