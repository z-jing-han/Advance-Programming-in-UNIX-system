# Lab 3 Gotoku

## Goal

1. Shared Library
2. Overwrite GOT Entry, simply put: replacing the function in the original library with your own custom shared library.

## Todo

> ⚠️ **Warning:**
> 
> According to the spec, if you're running locally, make sure to place a file `/gotoku.txt` under the root directory `/`
> ```
>  0 0 0 0 8 2 0 0 1
>  0 2 0 6 1 0 0 9 8
>  1 0 0 0 0 5 0 0 0
>  5 0 6 4 9 3 0 0 7
>  0 3 7 0 2 8 0 4 6
>  8 4 2 1 7 6 0 5 0
>  0 0 1 8 0 0 7 6 0
>  0 8 0 0 0 0 0 1 3
>  0 0 3 2 5 1 0 0 4
> ```
> Otherwise the file won’t be found during execution. For future labs too, if you're running locally, files are usually placed in the root directory.

1. How to compile a program into a library? How to use a library you compiled?
    Below is the `makefile` from the `dummy/` folder:
    ```makefile=
    CC = gcc
    CFLAGS = -Wall -g -fPIC

    TARGET = gotoku.local

    LIB_TARGET = libgotoku_dummy.so

    all: $(TARGET) $(LIB_TARGET)

    LIB_OBJS = libgotoku_dummy.o

    $(LIB_TARGET): $(LIB_OBJS)
        $(CC) -shared -o $(LIB_TARGET) $(LIB_OBJS)

    libgotoku_dummy.o: libgotoku_dummy.c libgotoku.h
        $(CC) $(CFLAGS) -c libgotoku_dummy.c

    OBJS = gotoku.o

    $(TARGET): $(OBJS) $(LIB_TARGET)
        $(CC) $(CFLAGS) -o $(TARGET) $(OBJS) -L. -lgotoku_dummy

    gotoku.o: gotoku.c libgotoku.h
        $(CC) $(CFLAGS) -c gotoku.c

    clean:
        rm -f $(TARGET) $(OBJS) $(LIB_TARGET) $(LIB_OBJS) libgotoku_dummy.so libgotoku.so *.o

    .PHONY: clean

    run_dummy:
        LD_LIBRARY_PATH=. ./gotoku.local

    preload:
        LD_PRELOAD=./libgotoku.so LD_LIBRARY_PATH=. ./gotoku.local
    ```
    This is the makefile for the ex1 (10%). It looks intimidating but it's really doing three things:
    1. Compiles a shared object file (the library), `libgotoku_dummy.so`
    2. Compiles an executable and links it with the above object file, `gotoku.local`
    3. When running `gotoku.local`, links the object files

    Here’s the sequence:
    ```makefile
    gcc -Wall -g -fPIC -c libgotoku_dummy.c
    # Generates libgotoku_dummy.o, just compiling .c to .o
    gcc -shared -o libgotoku_dummy.so libgotoku_dummy.o
    # Generates libgotoku_dummy.so, compiling .o to .so
    gcc -Wall -g -fPIC -c gotoku.c
    # Generates gotoku.o, compiling .c to .o
    gcc -Wall -g -fPIC -o gotoku.local gotoku.o -L. -lgotolu_dummy
    # Generates gotoku.local, compiles gotoku.o to executable and links the above library located in current directory (.) 
    ```
    There are two kinds of things involved:
    1. library (`.c`->`.o`->`.so`) — this is not for execution, but to be linked by others
    2. Executable (`.c`->`.o`->`exe`) — this is the actual runnable binary, which needs to link libraries if needed

2. What to write in the shared object (`.so`, i.e., library)?
    1. First, look at `libgotoku_dummy.c` in the dummy folder. That’s the original library. Your goal is to replace this.
    2. Before replacing it, you can reuse stuff inside. You can use `dlsym()` to fetch the original library's symbols and reuse its functions.
    3. For part 2-A (10%), the requirement is just to solve the Sudoku — no additional limitations. The approach in `local_lib_modify_gop/` folder is simply to modify the content of `gop_1()`
        3-1. Use `lib_constructor` to find the original symbols (step 2)
        3-2. `game_init`
        3-3. `game_load` and solve the Sudoku using DFS
        3-4.  Overwrite `gop_1()` to apply the solved values (conceptually function overwrite)
        
    Since we want to link our own custom library at runtime instead of the original dummy one, run:
    ```bash
    LD_PRELOAD=./libgotoku.so LD_LIBRARY_PATH=. ./gotoku.local
    # Set two environment variables: first is which .so to load, second is library path, third is the executable
    ```
    
3. What about 2-B (10%)? Folder: `local_lib/`
    There are more restrictions now. But actually, my 2-A only violated this rule:
    >> Your solver an only call the `gop_*` functions to walk in the puzzle, or modify the GOT table
    In other words, you're not allowed to modify gop_*, but in 2-A I did change gop_1.
    So in this part, the goal becomes the next one: **modify the GOT table**
    
    The spec provides a Python script (`get_got.py`) which reads the relative addresses of the `gotoku.local` functions and stores them in `got.txt`. So now you can just read from that file to get the relative addresses of the `gop_*` functions.
    
    Then during `game_load`, you simply replace the function addresses in the GOT table with the functions you want to use (fill the action function pointers). The logic is similar to the previous step's `gop_1`, but instead of calling a function directly, now you're overwriting an address.
    
4. And what about the remote part (6. 30%)? Folder:`remote/`
    What you do is compile your own library and send it to the server, and the server links your library and runs it.
    
    However, you won't know the `gop_*` addresses on the `server` in advance. But the TA provides the actual binary that the server is executing, so you can extract the `gop_*` addresses from that — just hardcode those addresses into your program and send it.
    
Steps 3, 4, and 5 are likely graded based on the output only.

Step 6 There's a long section after this — that's probably just for verification, not very important.