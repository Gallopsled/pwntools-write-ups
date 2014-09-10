# Vortex 12

This is the same challenge as Level 8, but with NX enabled.

We leverage pwntools' `gdb.find_module_addresses(binary, ssh=shell)` to grab all of the addresses for the libraries, then use pwntools' `ROP` module to generate a ROP stack to load some shellcode.  The shellcode then does the exact same thing as level 8.

The interesting part for this challenge was where to put the ROP.  The buffer overflow is `strcpy` and I didn't want to restrict the ROP in any way.  It turns out that you can store arbitrary data in the `argv[]` array, so I put it there.  I use GDB to do stack-hunting to find the absolute address of my `argv[]` to do the pivot.

Again, I use hellman's `r.sh` so that stack addresses in GDB and not-GDB are connsitent.