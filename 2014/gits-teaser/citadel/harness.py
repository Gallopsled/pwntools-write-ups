#!/usr/bin/env python2

from pwn import *
import os, signal
context.log_level = 1000

with tempfile.NamedTemporaryFile() as fd:
    s = randoms(12)
    fd.write(s)
    fd.flush()

    try:
        p = process(["./doit.py", "SILENT"])

        p.sendline("base64 " + fd.name)
        if p.recvline(timeout = 10).strip() == b64e(s):
            print "ok"
        else:
            print "not ok"
    finally:
        p.close()
