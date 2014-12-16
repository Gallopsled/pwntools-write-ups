#!/usr/bin/env python2
from pwn import *

context.log_level = 1000
with tempfile.NamedTemporaryFile() as fd:
    s = randoms(12)
    fd.write(s)
    fd.flush()

    try:
        l = listen(0)
        l.spawn_process('./8ff953dd97c4405234a04291dee39e0b')
        p = process(["./doit.py", "SILENT", "HOST=localhost", "PORT=" + str(l.lport)])

        p.sendline("base64 " + fd.name)
        if p.recvline(timeout = 10).strip() == b64e(s):
            print "ok"
        else:
            print "not ok"
    finally:
        l.close()
        p.close()
