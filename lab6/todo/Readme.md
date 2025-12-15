# lab6

## Goal

Very similar to lab5 — the goal is still to extract data from the server that’s not accessible under normal circumstances. But while lab5 uses a **race condition**, this one uses **buffer overflow**.

Each task basically requires:
1. Open `/FLAG`
    `fd = open("/FLAG")`
2. Read the content of `/FLAG`
    `read(fd, buf, buf_size)`
3. Output the read content to `stdout`
    `write(1, buf, buf_size)`
4. Exit the program
    `exit(0)`

Also, the file descriptor (fd) will always be 3 (from Discord), since it’s the first file opened.

## todo

This time, it’s recommended to use pwndbg to examine the stack — it’s more convenient.
So how to debug?
When running the script, pass in the argument `local` — this will print out the PID, and then you can attach to the PID for debugging.

> ❗ **Danger:** 
> 
> Please remember to prepare the `/FLAG` in the root dir.

### 1
Looking at the server code, it’s simple — just send your assembly code and it’ll execute directly.

Line before `chal_4.py:27` are the given example script.
The part we need to write is basically the `asm_code` variable content.
Then on `chal_4.py:62`, it gets converted to bytecode and sent.
Just receive the output afterward.

There are a total of four `syscall` calls, each corresponding to the four actions mentioned above.
Some extra lines move `rsp`, but those are not important.
You can try deleting any line that doesn’t set a parameter to see if it still works.
I placed the string `"/FLAG"` on the stack in `chal_1.py:35~38`

### 2
The assembly part should be exactly the same.
Now the problem is that the shellcode can’t be directly executed anymore, so you need to trigger a buffer overflow to run it.
`bof1.c:80` calls `task()` — this function lets us input data.
However, it reads 256 bytes but only allocates 40 bytes of space.
So we can overflow and overwrite the return address:
```
| ... other data   | <-rsp
| buf3             |
| ... other data   |
| buf2             |
| ... other data   |
| buf1             |
| ... other data   |
| task return addr | (should be the address at bof1.c:81)
```
The goal is to replace the return address of task with the address of msg (which contains the same shellcode as in ex1).
So we need to overflow past the buffer to overwrite task's return address.

In `chal_2.py:60`, I send 56 As first (the number needs to be determined with debugger):
```
| ... other data   | <-rsp
| buf1             |
| ... other data   |
| buf2             |
| ... other data   |
| buf3 (AAAA       | (56 A's)
| AAAAAAAAAA       | 
| task return addr | (should be the address at bof1.c:81)
```

Then, in `chal_2.py:62`, 9 + 8×7 bytes are received and printed (9 is the output, 8×7 is what I sent).
It returns the task's return address.
\+ 0xe5587 is used to calculate the address of msg (`bof1.c:12`), using gdb.
in `chal_2.py:61`, I send another 8×13 A’s plus the calculated msg address:
```
| ... other data   | <-rsp
| buf3             |
| ... other data   |
| buf2 (AAAA       | (8×13 A's)
| AAAAAAAAAA       |
| buf1 (AAAA       | 
| AAAAAAAAAA       | 
| msg addr         | (now replaced)
```
Next, the third input isn’t important.
Finally, send the asm_code into msg.

### 3
In theory, the second question is the same, except now there's a canary enabled, so the stack looks like this:
||I’m not sure why the buffer order is reversed in Q2 and Q3, but this is what gdb shows||
```
| ... other data   | <-rsp
| buf1             |
| ... other data   |
| buf2             |
| ... other data   |
| buf3             |
| ... other data   |
| canary           |
| task return addr | (should be the address at bof2.c:81)

```
The canary is a protection mechanism to prevent overflows.
So now you need to preserve and restore the canary while also overwriting the return address.

The steps become:
First, record the **canary**:
```
| ... other data   | <-rsp
| buf1 (AAAA)      | sending here
| AAAAAAAAAA       |
| buf2 (AAAA)      |
| AAAAAAAAAA       |
| buf3 (AAAA)      |
| AAAAAAAAAA       |
| canary           |
| task return addr | (should be the address at bof2.c:81)
```
Then record the return address to calculate msg address:
```
| ... other data   | <-rsp
| buf1 (AAAA)      | 
| AAAAAAAAAA       |
| buf2 (AAAA)      | sending here
| AAAAAAAAAA       |
| buf3 (AAAA)      |
| AAAAAAAAAA       |
| AAAAAAAAAA       | (overwrites it)
| task return addr | (should be the address at line 81)
```
Then write back **canary + msg addr**: (Check by debugger, there a word between canary and return addr, I ignore it here, but it not important)
```
| ... other data   | <-rsp
| buf1 (AAAA)      | 
| AAAAAAAAAA       |
| buf2 (AAAA)      | 
| AAAAAAAAAA       |
| buf3 (AAAA)      | sending here
| AAAAAAAAAA       |
| canary           | (overwritten)
| msg return addr  | 
```
Then send the `asm_code`.


### 4

Basically, there’s no more `msg` variable to work with.
```
| ... other data   | <-rsp
| buf1             |
| ... other data   |
| buf2             |
| ... other data   |
| buf3             |
| ... other data   |
| canary           |
| task return addr | (should be the address at line 81)
```

```
| ... other data   | <-rsp
| buf1             |
| ... other data   |
| buf2             |
| ... other data   |
| buf3             |
| ... other data   |
| canary           |
| ROP code         |
```
Use ROP to simulate the desired assembly behavior (refer to the spec or Hint).
The space for `"/FLAG`" and the buffer for its content can be repurposed from the above buffers.

So how do you find the base addr and return addr?
Use `objdump` to locate the call `<task>` instruction.

To find specific ROP gadgets, use the instructions in the spec + grep.
There’s only one `syscall; ret;` — I found it using pwndbg, referred from comment

