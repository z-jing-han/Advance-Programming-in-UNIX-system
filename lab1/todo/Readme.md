# Lab1 docker & pwntool

## Goal

What this lab is about:
1. Set up the environment
2. Get familiar with pwntool

There’s a “pow (proof-of-work)” that pops up in the middle—you can just ignore this part. It’s just a verification method. Just use the given code and move on.

Choose any environment setup you like. Most people probably use **WSL**, but I used **VMware + Ubuntu 24.04** and it worked fine. (Also, judging from later labs, doing the assignments on MacOS might cause a lot of trouble, so it’s better to get a Linux machine.)

UPDATE: I Change the environment into WSL (after the end of semester, no reason), and I also add some bind mount term in `up-runtime/start.sh` to let the lib mount to container. Just for fun.

You can think of pwntool as a scripting library to help with communication/interaction tasks.

The main features used fall into three types:
1. Connecting — the two methods below are essentially the same. The second one is just more convenient for local testing.
    remote
    ```py
    conn = remote("ip", port)
    conn.close()
    ```
    local
    ```py
    r = process("command or exe", shell = False)
    r.close()
    ```
2. ending data — functions starting with send
    ```py
    conn.sendline("A")
    ```
3. Receiving data — functions starting with recv
    ```py
    one_line = conn.recvline()
    ```

Anyway, this is just a toolkit for communicating with your target. You can look up the library for how to use it ||or ask ChatGPT||

## Todo

3. ***simple HTTP challenge***
    Just fetch the content from that URL and print it.
    You only need to send an HTTP Request.

4. A mini game
    This is for practicing pwntools. By observing guess.dist.py (the server's behavior), you can figure out how to interact with the server (e.g., what messages to expect, how to respond).
    You probably don’t even need to beat the game—just interacting correctly is enough.
    ||Ask ChatGPT to solve the game||
