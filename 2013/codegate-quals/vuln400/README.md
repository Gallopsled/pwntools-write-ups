# Codegate 2013 Vuln 400 Writeup

## Initial Investigation

Cool, we're actually getting to something with mitigations!

    checksec.sh --file 7b80d4d56c282a310297336752c589b7
    RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
    Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   7b80d4d56c282a310297336752c589b7

    7b80d4d56c282a310297336752c589b7: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xff0014df6d9c8b3dfb72355bc23d76e370ac5687, stripped

Let's see what it does...

     _______________________________
    /==============================/
    |     Onetime Board Console    |
    /------------------------------/
    |          | WELCOME |         |
    |__________|_________|_________|
    |          W  a  i   t         |
    ++++++++++++++++++++++++++++++++

And then we do wait.  For thirty seconds.

    .text:08048A7B     mov     dword ptr [esp], 1Eh        ; seconds
    .text:08048A82     call    _sleep

Let's get rid of that.  Probably for throttling purposes during the CTF.

    python -c 'print "\x90"*100' > nops
    dd conv=notrunc if=nops of=7b80d4d56c282a310297336752c589b7 seek=$((0xa82)) bs=1 count=5

Cool, what can we do? Looks like we can create/edit/delete/view replies with three fields.  And then we can leave messages on an Auto Reply system or whatever.

    1. Write
    2. Read
    3. Exit
    => 1
    Author : my_author
    Title : my_title
    Content : my_content
    1. Write
    2. Read
    3. Exit
    => 2
        | number| author               | title
        -----------------------------------------------
        |     1 | my_author            | my_title
        -----------------------------------------------
        Number : 1
            ===================================
            || 1 || my_author            || my_title
            ===================================
            |content | my_content
            ===================================
                |
                |====> Welcome, It's Auto reply system
            1. delete  2. modify  3. reply  4. back
            => 1
    Cannot Deleted. There's at least one or more replies on it

Huh, so delete's broken or something. Let's look into that.

## Reverse Engineering & Disassembly

So we've got a program which has is somewhat like a forum/bbs -- you
can create a new post, and you can create replies.

Everything is stored on the heap.  There are two main structures.

### Post Structure

The `post` is pretty basic.  It implements a doubly-linked list,
has a few function pointers, a few pointers to strings, and a
pointer to the first entry in the singly-linked list of replies.
It also has a `magic` field, which changes based on whether the
`post` has been modified.

    00000000 post            struc ; (sizeof=0x30)
    00000000 num_replies     dd ?                    ; XREF: ...
    00000004 next            dd ?                    ; XREF: ... ; offset
    00000008 prev            dd ?                    ; XREF: ... ; offset
    0000000C read_input      dd ?                    ; XREF: ... ; offset
    00000010 do_free_detect  dd ?                    ; XREF: ... ; offset
    00000014 reply_head      dd ?                    ; XREF: ... ; offset
    00000018 reply_count     dd ?                    ; XREF: ...
    0000001C author_100h     dd ?                    ; XREF: ... ; offset
    00000020 title_100h      dd ?                    ; XREF: ... ; offset
    00000024 content         dd ?                    ; XREF: ... ; offset
    00000028 magic           dd ?                    ; XREF: ...
    0000002C rand            dd ?                    ; XREF: ...
    00000030 post            ends
    00000030

### Reply Structure

The `reply` structure is also pretty basic.  It imlements a single
forward link, another `magic` value, a pointer to the reply text,
and a single function pointer.

    00000000 reply           struc ; (sizeof=0x1C)
    00000000 head            dd ?
    00000004 magic           dd ?                    ; XREF: ...
    00000008 number          dd ?
    0000000C reply_text      dd ?                    ; XREF: ... ; offset
    00000010 set_BABEFACE    dd ?
    00000014 do_free         dd ?                    ; XREF: ... ; offset
    00000018 next_rec        dd ?                    ; XREF: ... ; offset
    0000001C reply           ends
    0000001C

## Le Bugs

There are a few bugs/gotchas.  The first of these is that the counter `reply_count` is only ever interacted with as a single byte.  This is particularly apparent in the delete routine, which we noticed was bugged earlier.  We can easily overflow this counter back to zero by creating a bunch of replies.

```c
if ( SLOBYTE(post->num_replies) <= 0 )
{ ... }
else
{
    puts("Cannot Deleted. There's at least one or more replies on it");
}
```

The second bug is that the function pointer `do_free` is initialized if-and-only-if the `magic` on the `post` indicates that it is unmodified.

```c
if ( post->magic == 0xDEADBEEF )
{
  for ( reply = post->reply_head; reply->next_rec; reply = reply->next_rec )
  {
    reply->set_BABEFACE = (int)set_BABEFACE;
    reply->do_free = do_free;
  }
}
```

However, there is trivial detection for this.  The authors were quite loud about where the bug is.  The trivial detection only checks the first two replies, though.

```c
reply = post->reply_head;
for ( i = 0; i <= 1; ++i )
{
    if ( reply->do_free != do_free )
    {
        puts("Detected");
        exit(1);
    }
    reply = reply->next_rec;
}
```

So we have a relatively traditional uninitialized function pointer that we can influence from old heap data.  How to get at the heap?  After looking at all of the `malloc` calls in the binary, one stands out.  When entering `content` for the post, `8000` bytes of our data is read into a `10000` byte stack buffer.  This buffer is then `strlen()`'ed, and a new heap allocation is created to hold exactly that data.  Now we control a boatload of heap.  Luckily, none of the important addresses control NULLs.

## Exploit

Exploitation is pretty straightforward.

0. Create three posts (#1-3)
0. The #2 should have a huge `content`.  I used a cyclic fill pattern to find offsets within it on crashes.
0. Create enough replies to reset the `reply_count` counter to zero.
0. Free the middle post.  This frees the giant `content` heap buffer.
0) Create two new posts (#4-5)
0. On post #4, overflow the `reply_count` and free

By manipulating the `content` of post #3 such that we can pass the check on the first two replies (the "Detected" check) and so that the function pointer on the third reply is `system`, we can call `system` on the text of the reply.