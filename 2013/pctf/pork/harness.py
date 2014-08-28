#!/usr/bin/env python2

from pwn import *
context.log_level = 1000

with tempfile.NamedTemporaryFile() as fd:
    s = randoms(12)
    fd.write(s)
    fd.flush()

    p1 = process(['./pork-patched'])
    try:
        p2 = process(["./doit.py", "SILENT"])

        p2.sendline("base64 " + fd.name)
        if p2.recvline().strip() == b64e(s):
            print "ok"
        else:
            print "not ok"
    finally:
        p1.kill()
