#!/usr/bin/env python2

from pwn import *
context.log_level = 1000

with tempfile.NamedTemporaryFile() as fd:
    s = randoms(12)
    fd.write(s)
    fd.flush()

    process('./94dd6790cbf7ebfc5b28cc289c480e5e') 
    p = process(["./doit.py", "SILENT", "HOST=localhost", "PORT=6666"])

    p.sendline("base64 " + fd.name)
    if p.recvline().strip() == b64e(s):
        print "ok"
    else:
        print "not ok"
