#!/usr/bin/env python2
from pwn import *
context.log_level = 'CRITICAL'

with tempfile.NamedTemporaryFile() as fd:
    s = randoms(12)
    fd.write(s)
    fd.flush()

    try:
        p = process('./94dd6790cbf7ebfc5b28cc289c480e5e')
        sploit =  process(["./doit.py", "SILENT", "HOST=localhost", "PORT=6666"])

        sleep(2)
        sploit.sendline("base64 " + fd.name)
        if sploit.recvline().strip() == b64e(s):
            print "ok"
        else:
            print "not ok"
    finally:
        p.close()
        sploit.close()
