#!/usr/bin/env python3
# -*- coding: utf-8 -*-
## Lab sample file for the AUP course by Chun-Ying Huang

import sys
from pwn import *
from solpow import solve_pow
import base64
import zlib
import itertools
from warnings import filterwarnings
filterwarnings("ignore")

if len(sys.argv) > 1:
    ## for remote access
    r = remote('up.zoolab.org', 10155)
    solve_pow(r)
else:
    ## for local testing
    r = process('../spec/guess.dist.py', shell=False)

def sendmsg(m):
    ## Modify from /.guess.dist.py sedmsg(m) function: 'big' -> 'little'
    zm = zlib.compress(m)
    mlen = len(zm)
    return base64.b64encode(mlen.to_bytes(4, 'little') + zm).decode()

def decode_msg(msg):
    ## Modify from /.guess.dist.py recvmsg(m) function: 'little' -> 'big', no need to encode input m (is byte already)
    msg = base64.b64decode(msg)
    mlen = int.from_bytes(msg[0:4], 'big')
    if len(msg)-4 != mlen:
        sys.exit(1)
    m = zlib.decompress(msg[4:]).decode()
    return m

def get_ab(guess, answer):
    ## Copy from /.guess.dist.py line 39, 40, to get the result of game
    a = sum([ 1 if guess[i] == answer[i]   else 0 for i in range(4) ])
    b = sum([ 1 if guess[i] in set(answer) else 0 for i in range(4) ]) - a
    return a, b

def solver(r):
    ## Interative with remote server

    ## Recive init msg
    init_msg = decode_msg(r.recvline().strip())
    print(init_msg)
    
    ## Init game state
    possible_answers = [''.join(p) for p in itertools.permutations('0123456789', 4)]
    current_guess = "1234"
    num_A, num_B = 0, 0

    for i in range(10):
        ## Recive round start msg
        round_start_msg = decode_msg(r.recvline().strip())
        print(round_start_msg, current_guess, sep = '')
        
        ## send to current guess to remote server
        r.sendline(sendmsg(current_guess.encode()))

        ## Reciver server relpy about game state
        round_result_msg = decode_msg(r.recvline().strip())
        num_A = int.from_bytes(round_result_msg[3].encode())
        num_B = int.from_bytes(round_result_msg[8].encode())
        print("           Remote Server Reply: ", num_A,round_result_msg[4],num_B,round_result_msg[9], sep='')
        
        ## Recive round state msg
        round_state_msg = decode_msg(r.recvline().strip())
        print(round_state_msg)
        
        ## Win condition
        if num_A == 4:
            break

        ## update game state by Knuth's Algorithm
        possible_answers = [num for num in possible_answers if get_ab(current_guess, num) == (num_A, num_B)]
        if len(possible_answers) == 1:
            current_guess = possible_answers[0]
        else:
            ## Minimax Strategy
            minmax_value = {}
            for guess in possible_answers:
                feedback_count = {}
                for possible_answer in possible_answers:
                    feedback = get_ab(guess, possible_answer)
                    feedback_count[feedback] = feedback_count.get(feedback, 0) + 1
                minmax_value[guess] = max(feedback_count.values(), default = 0)
            current_guess = min(minmax_value, key = minmax_value.get)

print('*** Implement your solver here ...')
solver(r)
r.close()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
