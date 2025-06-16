# Homework 2

## Goal

Practice the `ptrace` syscall by designing an instruction-level debugger.

Below are the course examples I referenced. If you've downloaded the course materials, you should be able to find them:

1. [autodbg.cpp](https://github.com/chunying/up-inclass/blob/master/ptrace/autodbg.cpp)
    This was mainly used as the skeleton. It includes forced insertion of `0xcc` at a certain point and modifying the value of some buffer (as I recall—check the course video or slides for details).

2. [ptools.cpp](https://github.com/chunying/up-inclass/blob/master/ptrace/ptools.cpp), [ptools.h](https://github.com/chunying/up-inclass/blob/master/ptrace/ptools.h)
    These two are needed by `autodbg.cpp`, mainly used to read the memory segment of the child process. ||I didn’t modify them at all and used them directly||

3. [syscall.c](https://github.com/chunying/up-inclass/blob/master/ptrace/syscall1.c)
    Mainly used to reference how to write the `syscall` instruction.


## todo

### Overall Flow
1. Create a child process to execute the program to be debugged, from `autodbg.cpp`
2. Use `auxv` to find the Entry Point
3. Use `ptools.h` to find the base address
4. Insert a breakpoint with ID -1 at the Entry Point
5. Call `ptrace(CONT)` which will stop at the breakpoint from step 4.
6. Perform actions based on different commands, by `exeSDBcommand()`
    6-1.  Commands that do not change control flow: `return 0`
        Perform the required actions, and the loop continues at `sdb.cpp:364`
        
    6-2. `"si"` 
        Not hitting a breakpoint  -> `return 1`
        Hitting a breakpoint -> `return 2`
    
    6-3. `"cont"`
        `return 1`
    
    6-4. `"syscall"`
        Hits syscall -> `return 0`
        Hits breakpoint  -> `return 2`
        
|`return`| Meaning | Example |
|:--:|:--:|:--:|
| 0 | No need to check status<br>1. Control flow not changed<br>2.`ptrace(SYSCALL)` hits a syscall | 1. `info`, `patch`, `break`, etc<br>2. Special case, handles everything immediately|
| 1 | Need `waitpid` to check status<br>Also need to check for breakpoints | 1. `cont`<br>2.`si` not hitting a breakpoint |
| 2 | Already checked status via `waitpid`<br>But still need to check for breakpoint | `si` or `syscall` hitting a breakpoint |

These are self-defined. Feel free to modify.

Next is the explanation of how breakpoints are handled, which will help explain why the above distinction is necessary.

### break point

1. Inserting a breakpoint replaces the original byte with `0xcc`. The original byte is stored in a struct.
2. Situations when a breakpoint is encountered:
    2-1. Actually hit (executed `0xcc` and got stopped)

    How to determine this case? Check whether `regs.rip - 1` is a breakpoint.
    ```
    0x100: 11 22
    0x102: 11 22 <- if there's a breakpoint here  
    Actual situation:
    0x102: cc 22 # regs.rip = 0x103, regs,rip - 1 = 0x102
    ```

    2-2. Not hit yet, but current `regs.rip` is a breakpoint

    After executing command at `0x100`
    ```
    0x100: 11 22
    0x102: 11 22 <- break point
    Actual situation:
    0x102: cc 22 # regs.rip = 0x102
    ```
    
    In the first case, adjust `rip--`, because `0xcc` is 1 byte, to become the second case.

3. What to do when hitting a breakpoint?
    3-1. Mark the breakpoint as currently hit via variable `hit`
    3-2. Do **not** immediately recover (`0xcc` -> `0x11`)
    Only recover when control flow changes , such as `si`, `cont` or `syscall`, using `recovery_oneStep_restore(pid_t)`
    
    3-3. How to handle it?  ~~from the function name it’s self-explanatory~~
        3-3-1. Recover the breakpoint, `0xcc` -> `0x11`
        3-3-2. Use `ptrace(SINGLE_STEP)` to step over the breakpoint
        3-3-3. Restore the breakpoint, `0x11` → `0xcc`
    
    This ensures that the breakpoint continues to work properly.
    
    Since step 3-3-2 requires `waitpid` to check the status before proceeding, we cannot rely on outer `waitpid` calls anymore—hence we must `return 2`.
    
    Similarly for `syscall`: we also need `waitpid` to check the situation and decide whether to `return 0` (not hitting breakpoint, handle syscall directly) or `return 2` (hitting breakpoint). In any case, don’t `return 1`.

### disassemble
There are only two scenarios where disassembly output is needed:
1. After verifying where is hit a breakpoint
2. syscall

Actually, the spec is quite clear here—as long as control flow returns to our hands.

### poke byte
```cpp
unsign char poke_byte(pid_t child, unsign long addr, unsign char byte);
```
This function is used whenever you need to modify a byte—whether it’s `patch`, inserting breakpoints, or recovering breakpoints, all of these call this function.

Align to a word boundary (address must end in 8 or 0) before inserting (need to calculate offset).
This way, you can align with memory segments and ensure you're in a writable area with just one insert.

If `ptrace(PEEK_TEXT, addr)` fails, `return (unsign char)0`, then check with `error`.
If successful, return the original byte.

### About DEMO

Most of the points are already covered above.
The only remaining issue: how to handle dynamically linked programs (public example 1–2)
All I can say is—`autodbg.cpp`, which I used, already handles this. I didn’t really do any additional processing.
The TA found it strange that it worked without extra handling, but they let me pass.
After thinking about it later, I believe the reason is that `autodbg.cpp` uses `ptrace(TRACE_ME)` in the child process.
So tracing only starts after the program is already running? That way, when I read `mmap`, I get the actual memory?

### A failed control flow
```
Hit a breakpoint  
Immediately recover  
Then, after handling control flow, restore the breakpoint
```
This flow becomes very problematic when dealing with breakpoints on `jump`-type instructions, because it’s hard to remember how to restore the breakpoint. (It’s doable, but the code becomes messy.)
Also, you need to separately determine whether to output info in many places (which makes the code even messier).
This wrong flow passed all the public tests but only passed one hidden test.
||By the way, this broken logic passed all the hidden tests from the year before I took the course||
Using this poor flow, I managed to fix only one hidden test case within three hours. So during the first demo, I only got a 70.
Only after that did I go back and rethink the entire flow.
