# Vortex 11

Simple heap corruption vulnerability.  If you spam data at it, you'll see that you get a write-what-where.

We nuke the GOT entry for `_exit` with a pointer to our shellcode in the heap buffer, which is at a predictable address.