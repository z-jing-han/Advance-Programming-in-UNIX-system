# Homework 1

## Goal

Looks like this is a brand new assignment created by the current TA.

Hmm, the explanation alone took over an hour—it's best to record both video and audio to really understand what the assignment is about.

Essentially, this is about implementing the ***zopline*** paper. The core concept is to replace `syscall` with `call rax` in order to modify the behavior of syscall. In this assignment, that modification is mostly to implement a logger.

Also, this assignment heavily uses a debugger, typically `gdb`, but because this task involves lots of assembly and stack manipulation, the TA strongly recommends using `pwndbg` instead. The advantage of the latter is that it displays stack, register, backtrace, etc., at each step, so you don’t need to keep typing commands like in `gdb`. The TA provided a sample debugging method in the spec under Hint 1.

## todo

This line should be set at host, not in container.
```sh
sudo sh -c "echo 0 > /proc/sys/vm/mmap_min_addr"
```

### Part 1
This part has a step-by-step guide in the spec. It’s essentially replicating the approach from the zopline paper.

#### ex1
The spec explains it quite clearly:
1. Use `mmap` to allocate memory.
2. Fill `0x0` (0) ~ `0x199` (511) with `NOP (0x90)`.
3. Put the code to be processed from `0x200` onwards.

This step is just to test whether the logic works after executing `call rax` and jumping to the logic after `0x0` ~ `0x199`.
Basically, convert `write(STDOUT, "Hello from trampoline!", 23)` into assembly and then into bytecode.

#### ex2
This is the most complex step, the core of the ***zopline*** paper.

I’ll write about some problems I encountered:

1. What exactly is the process?
    When I first read the spec, I didn’t quite get the whole flow. I just knew it involved converting from C to assembly and vice versa.

    The actual process is as follows:
    1. After replacing `syscall` with `call rax`, it jumps into the range 0x0 ~ 0x199 (by the syscall number).
    2. Since this range is filled with `NOP (0x90)`, the `rip` (program counter) will slide through to position `0x200`.
    3. In ex1, `0x200` holds `write(STDOUT, "Hello from trampoline!", 23)`, but now it needs to jump to a custom program we want to execute (Here is `void trampoline()`, which fill assembly in its implenetation).
    4. What needs to be done here? To modify syscall behavior, it’s easier to write in C.
        So this is the conversion: `void trampoline()` in assembly -> `int handler()` in C.
    5. After modifying the syscall behavior, we need to go back to executing the syscall using assembly.
        This is the conversion: `int handler()` in C -> `void __raw_asm()` in assembly.
    
    The difference between C function arguments and syscall arguments is covered in spec Hint 4.
    
    Below is the `rip`-perspective view:
    ```
    0xsysadr: call rax  (original syscall, assume syscall number is 0)
    0x000000: NOP
    ...
    0x000199: Nop
    # The following is the program to jump to void trampoline(); addr of trampoline is separately computed
    0x000200: movabs [64-bit addr (8-byte)],%r11
    0x00020a: jmp    %r11
    # Jump to trampoline()
    0xtrampo: mov %r10, %rcx       # Fill arguments per hint
    0xtrampo: push %rsp            # These three lines align the stack to 16 bytes
    0xtrampo: push (%rsp)          # Technically needed only in ex3
    0xtrampo: andq $-16, %rsp
    0xtrampo: push %rax            # Per handler args, seventh arg is on stack. Push twice for alignment
    0xtrampo: push %rax
    0xtrampo: call handler
    # Jump to handler
    # The handler eventually calls trigger_syscall, defined in assembly but exposed to C via extern
    trigger_syscall(rdi, rsi, rdx, r10, r8, r9, rax);
    # Jump to trigger_syscall:
    0xtrigge: mov 8(%rsp), %rax    # Return addr is at top, second entry is pushed %rax
    0xtrigge: mov %rcx,  %r10      # As per hint
    0xtrigge: syscall
    0xtrigge: ret
    # Return to handler
    return trigger_syscall(rdi, rsi, rdx, r10, r8, r9, rax); # # trigger is done here
    # handler returns to trampoline()
    0xtrampo: add $16, %rsp        # Remove the two pushed %rax
    0xtrampo: movq 8(%rsp), %rsp   # Restore aligned stack
    # Now top of the stack is the return addr pushed with the original call rax
    # We can now return to continue original execution
    ```

2. How to replace `syscall` with `call rax`?
    You need a disassembler tool. In class, teacher teachs ||in five sec|| `capstone`, which is a library. Look it up; it’s not too hard to use.
    Once you locate the `syscall`, just rewrite the bytecode as `call rax`.
    
    Two things to be careful about:
    1. When rewriting, `ex2.c:113` has a check—if it's `trigger_syscall`, do not rewrite it. Otherwise it would endlessly become `call rax` -> `trigger_syscall` becomes `call rax` -> `call rax` -> `call rax`, and `syscall` never executes.
    2. The spec says to ignore the `vsyscall` memory segment. Originally in `ex2.c:143`, I did that, but it failed on hidden test 1 because the executable is named `vsyscall`. So I changed it to `ex3.c:182` style. ||Yeah, it’s super hacky||
    

#### ex3
If you’ve understood ex2, then ex3 doesn’t add anything too scary ||though new additions may break ex2||.
The idea is that we want to do additional things in the C handler function (like logging output), but due to syscall rewriting, we need a workaround to prevent library functions we use from being rewritten too, which could cause `for(;;);`.
The spec explains the workaround, so I won’t repeat it here.

Now let's discuss why the handler and assembly change in the new ex3 example.

1. Why is there a large block at the beginning of the handler?
    Refer to Spec Hint 5's link. It shows how the zopline paper handles `clone` and `clone3`. Basically, just copy-paste it. But note: In the original paper, the `retptr` variable is passed as a parameter to the handler. However, our spec limits the handler's format, so we can't pass it that way. So how do we get it?
    `clone` and `clone3` create child processes (like `fork()`), and the variable is used to inform the new process of its return address. That value is the same as the return address in the parent process—i.e., the one pushed by `call rax`.
    ||So my very unethical solution was to use a global variable to store that number||—see `ex3.c:52~53`. (Based on the Discord discussion) it’s supposed to be computed from the current stack state.
    One last thing: My implementation surprised the TA (probably only I wrote it that way), and when I shared it with classmates, the TA grilled them during their demos. They were asked: Why `push 8(rsp); pop retptr(rsp)` and not `push rsp`? What is `rsp` at that moment?
    Eventually, use a debugger to see the actual stack state at that point. Turns out, right before executing void `trampoline()`, a weird instruction (I forgot which) pushes `rbp` onto the stack. This is something C functions naturally do.

2. Assembly? Two extra parts in total:
    1. Beginning
        ```
        // workaround from TA for vfork
        " cmp $0x3a, %rax    \t\n"
        " jne asm_start      \t\n"
        " pop %rsi           \t\n"
        " pop %rsi           \t\n"
        " syscall            \t\n"
        " push %rsi          \t\n"
        " ret                \t\n"

        " asm_start:         \t\n"
        ```
        The comment is clear—if it’s the `vfork()` syscall, skip it. This is the TA’s workflow from Discord, so just paste it. Also, don’t rewrite this `syscall` during binary rewrite.
    2. Ending part: This is simpler. It’s from Step 2 (Updated on Apr. 16) of the spec. A lot of register states must be preserved, so we push them to the stack before the syscall and restore afterward. Mind the alignment.

### Part 2
This part is probably the easiest. It’s the most relaxing part of the whole assignment: just follow the example and output the required contents. ~~Although it’s relaxing, sometimes it can cause part1 to crash due to side effects. For now, I’ve explained the earlier parts first, though in practice, writing this part may require adjustments to part1.~~

You can refer to the sample `logger.c` in spec step3, under “The following is a sample implementation of a hook library:”
Just replace the `fprintf` portion with the spec-required logger format.
