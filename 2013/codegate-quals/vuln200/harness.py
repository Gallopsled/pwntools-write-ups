#!/usr/bin/env python2

from pwn import *
context.log_level = 1000

with tempfile.NamedTemporaryFile() as fd:
    s = randoms(12)
    fd.write(s)
    fd.flush()

    process('./5b7420a5bcdc1da85bccc62dcea4c7b8') 
    p = process(["./doit.py", "SILENT", "HOST=localhost", "PORT=7777"])

    p.sendline("base64 " + fd.name)
    if p.recvline().strip() == b64e(s):
        print "ok"
    else:
        print "not ok"
