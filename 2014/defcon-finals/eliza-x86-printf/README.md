# Eliza

This is the x86 version of the challenge.

There are two vulnerabilities leveraged in this exploit.

First, there's uninitialized stack data printed when doing the 'info' command.  By calling 'help', you can pre-load that area with a pointer into the loaded module.  ASLR is now defeated.

Second, there's a buffer overflow in the implementation of `my_printf`.  However, your buffer is effectively terminated by newlines or `NUL`s.  In order to get around this, we need to pivot.

The pivot is performed by loading a pointer to the `.data` area into `eax` (by means of `pop ecx` then `mov eax, ecx` gadgets).  Afterward, we go into the `get_command_line` routine, which reads the second stage into the `.data` area with a known base address.

Finally, we open the flag file and read it.  Because the binary is RELRO (or some other reason, perhaps) we have to load `ebx` with the address of the `.got.plt` area before making calls.

## Caveats

Because of file descriptor inheriting, the exploit may not work on your system unless you change the file descriptor for the `read` call.  `5` works in `python`, `3` works in iPython.

Additionally, this relies on pwntools auto-generation of some ROP stubs.  Because there's no blacklisting for addresses, if the address of a selected gadget contains a `0x10` byte, the exploit will fail.