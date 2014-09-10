# Vortex 10

This challenge requires pressing the F5 buttin in IDA pro, some brute forcing.

The challenge gathers a bunch of timing information, feeds it to `srand()` and then `rand()`, and you need to predict a value.

We use a helper C program with the logic lifted from Hex Rays to generate an approximation of the starting parameters, then duplicate the logic and search from Python.  We load `libc` since I don't trust that Python's `rand`/`srand` are the same.

Once we've found a match, we get a shell.