# Vortex 3

Simple buffer overflow that will write a pointer to our buffer anywhere in the binary.

We use this to overwrite the GOT entry for `_exit`.

