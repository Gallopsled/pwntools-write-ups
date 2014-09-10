# Vortex 8

Turns out `setresuid` and company are thread-specific.  This challenge exercises that.

The unprivileged thread is vulnerable to a stack-buffer overflow.  We leverage this to swap out the GOT entry for `_sleep` with a pointer to our shellcode, then call `_exit`.  When the second thread attempts to sleep next, it executes the second stage.

Yet again, this script uses hellman's excellent `r.sh` so that we can just script GDB to print out stack addresses for us and automate.