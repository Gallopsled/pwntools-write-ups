#!/usr/bin/env python2

from pwn import *
context.log_level = 1000

with tempfile.NamedTemporaryFile() as fd:
    s = randoms(12)
    fd.write(s)
    fd.flush()

    l = listen(0)
    l.spawn_process(['./ropasaurusrex-85a84f36f81e11f720b1cf5ea0d1fb0d5a603c0d'])
    p = process(["./doit.py", "SILENT", "HOST=localhost", "PORT=" + str(l.lport)])

    p.sendline("base64 " + fd.name)
    if p.recvline().strip() == b64e(s):
        print "ok"
    else:
        print "not ok"
