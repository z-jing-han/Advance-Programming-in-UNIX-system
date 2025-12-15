# Lab5

## Goal

Use a `race condition` to obtain specific content from the server.
The method to trigger the `race condition` is by sending data to the server.
||And I didn’t manage to solve the third one ~~even though I overheard someone explaining the problem during the demo and figured out what was wrong~~ so I missed out on an A+.||
||I only found someone’s solution on GitHub after the semester ended, and it turned out to be *surprisingly simple*.||

## todo

1. In `cha_1.c:show_fortune`, this function is executed by different threads each time. While reading a file, it stores the filename in the global variable at `cha_1.c:20`, creating a race condition:
    ```
    thread 1 37 and passes validation                                     line 39 reads thread 2’s requested file
    thread 2                           29 overwrites the global variable

    ```
    If the execution order is like above, you can read the unintended file.
    So just keep trying until you read something like `flag{....`

2. At `cha_2.c:56`, there's a `get_hostbyname2` call. Just run `man get_hostbyname2` and you’ll see this function is **not** thread-safe. Yep, that’s it.
    > ⚠️ **Warning:**
    > 
    > The issue isn’t the `ent` variable returned at `cha_2.c:56`—it’s a memory problem with the function itself.
    
    Also, using this method, it takes around 2–3 minutes to finally get the flag.
    The TA mentioned that if the data you send is correct, you’ll get it right away.
    ||But I didn’t have the ability to figure that out myself.||

3. At `cha_3.c:136` and `cha_3.c:161`, the file descriptor (`fd`) is being closed twice—it seems.
    So under some conditions, `"password.txt"` is opened, and its content ends up being empty, which means sending empty username and password would pass the test. ~~But I couldn’t reproduce it.~~
    According to the solution I eventually found, the key point I overlooked was how to **decode the cookie**.
    I assumed once you get the cookie’s value the first time, you could just reuse it. But at `cha_3.c:192`, there's clearly a validation check, and I just totally ignored it.
    After decoding the cookie, the race condition is actually super straightforward: just repeatedly send requests and hope the first one causes "password.txt" to be closed before the second reads it.
    ||Also, this program tends to fail during the first 5–6 runs, then starts succeeding consistently afterward.||