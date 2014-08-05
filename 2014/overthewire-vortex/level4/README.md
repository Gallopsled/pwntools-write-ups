# Vortex 4

`printf` format string vulnerability, combined with a bit of information about stack layout.  `argc` can be zero if expressly created that way via an `exec` call.  If `argv` is used to index the non-existed arguments, it can (in this case, does) index into the `envp` array.

For the sake of "because", this also auto-discovers the offset of the arguments needed to pass to hellman's `libformatstr`.

We use the format string to overwrite the GOT entry for `_exit`, and point it at our shellcode on the stack.  The absolute address of the stack is leaked by a small helper program run on the target system.