#!/usr/bin/env python2

from pwn import *
import os, signal
context.log_level = 1000

with tempfile.NamedTemporaryFile() as fd:
    s = randoms(12)
    fd.write(s)
    fd.flush()

    try:
        l = listen(0)
        l.spawn_process('./7b80d4d56c282a310297336752c589b7')
        p = process(["./doit.py", "SILENT", "HOST=localhost", "PORT=" + str(l.lport)])

        p.sendline("base64 " + fd.name)
        if p.recvline(timeout = 10).strip() == b64e(s):
            print "ok"
        else:
            print "not ok"
    finally:
        p.close()
        os.kill(l.proc.pid, signal.SIGKILL)
