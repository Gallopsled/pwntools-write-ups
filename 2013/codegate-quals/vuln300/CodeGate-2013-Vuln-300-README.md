# Codegate 2013 Vuln 300 Writeup

## Initial Analysis

The binary accepts data over stdin/stdout, and spits back at you a bunch of printable characters, appended with a number of your choosing.

    $ checksec.sh --file 8ff953dd97c4405234a04291dee39e0b
    RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
    No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   8ff953dd97c4405234a04291dee39e0b
    $ file 8ff953dd97c4405234a04291dee39e0b
    8ff953dd97c4405234a04291dee39e0b: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.18, BuildID[sha1]=0xe2aac24b3214869f3b7173a83dac8115ae4cd8ba, stripped

Example output

    ./8ff953dd97c4405234a04291dee39e0b
    Input Num : 10
    Input Msg : 10
    Reply :
    ABCDEFGHIJ10

The immediate thing I'd think with this problem is to provide just-too-large values, and overwrite something with the data that's appended.  Let's see if we can stick binary data on the end.

    python <<EOF | ./8ff953dd97c4405234a04291dee39e0b | xxd
    print 10
    print '\xfb\n\x00'
    EOF
    0000000: 496e 7075 7420 4e75 6d20 3a20 496e 7075  Input Num : Inpu
    0000010: 7420 4d73 6720 3a20 5265 706c 7920 3a20  t Msg : Reply : 
    0000020: 0a41 4243 4445 4647 4849 4afb 0a0a       .ABCDEFGHIJ...

Yep, our `\xFB` remains in the output.  Cool, let's dig in a bit.

## Disassembly & Reverse Engineering

The binary is extremely small.  Opening it up, you immediately see a `malloc` call, followed by what look like two constructors.  This is a guess based on the `*(DWORD*)arg0 = foo;` in the routines, the fact that one calls a similar routine, and that the second routine's `foo` has a function pointer at it.

After a bit of massaging, we arrive at the following:

      obj = (obj *)operator new(0x804);
      subclass((int)obj);
      printf("Input Num : ");
      fflush(stdout);
      sleep(2u);
      fgets(buf_800h, 0x800, stdin);
      count = atoi(buf_800h);
      memset(buf_800h, 0, 0x800u);
      printf("Input Msg : ");
      fflush(stdout);
      sleep(2u);
      fgets(buf_800h, 0x800, stdin);
      fflush(stdout);
      sub_8048840(obj, buf_800h, count);
      obj->vtable->vfunc(obj);

Note the virtual call at the very end.  Let's dig into `sub_8048840`.

    char *__cdecl sub_8048840(obj *obj, char *src_800h, int count)
    {
      char *result; // eax@5
      if ( count > 0x7FF )
      {
        result = strcpy(obj->string_800h, src_800h);
      }
      else
      {
        for ( i = 0; (count ^ (count >> 31)) - (count >> 31) > i; ++i )
          obj->string_800h[i] = i + 'A';
        result = strncpy(&obj->string_800h[count], src_800h, 0x800 - ((count ^ (count >> 31)) - (count >> 31)));
      }
      return result;
    }

What immediately stands out is the signed `int count`, which is only checked for an upper bound (this is the value we provide first).  Later on, some weird logic is done with bit-shifting.  Let's double-check the signed check in disassembly:

    cmp     [ebp+count], 7FFh
    jg      loc_80488DC

Yep.  Here's the disassembly that IDA chokes on so badly:

    mov     eax, [ebp+count]
    mov     edx, eax
    sar     edx, 1Fh
    mov     eax, edx
    xor     eax, [ebp+count]
    sub     eax, edx
    mov     edx, ds:g_counter
    cmp     eax, edx
    setnle  al

A quick Google on "sar 0x1F xor" gives us a first hit of ["Absolute value in asm"](http://dustri.org/b/absolute-value-in-asm.html), which gives us:

    sar edx, 0x1f
    xor eax, edx
    sub eax, edx

Yep, that's what it looks like.  So as long as `abs(count) > i`, it'll keep iterating.  No good.

### VTable Overwrite

However, right after the loop, there's the `strncpy` nugget which blindly accepts `count` as an index into the string.

We can supply an index of `-4`, and overwrite the `vtable` entry on the object.  As we found out earlier, we can supply raw binary data to be appended (as long as it is NULL-free) to the buffer.  In this case, it would really be 'pre-ended'.  The NULL limitation isn't really an issue, as the binary's address has no NULLs in it, and PIE is disabled.  If we had an ASLR bypass,

Once we've overwritten the vtable pointer, back in the main routine we get this:

    obj->vtable->vfunc(obj);

Which is effectively a controlled function call, with non-NULL data that we control as the first argument.  Recall earlier that NX is disabled, so if our data is ever copied to a static buffer, we can win quite easily.

In fact, this is exactly the case as in pwn200 -- the data from the second argument is copied into a large, statically-addressed buffer at `080491E0`.  All we need to do is fake a vtable.

## Exploitation

1. Provide a negative value (`-8`) for the `strncpy` to overwrite the `vtable` pointer of our heap object.
2. Create a fake vtable at `080491E0` by passing in `080491E4` as the first four bytes of the secondary buffer.  Add `080491E0` after that, since this will actually nuke the `vtable` pointer.  Add our shellcode after that.