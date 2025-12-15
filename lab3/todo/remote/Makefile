CC = gcc
CFLAGS = -Wall -fPIC

LIB_TARGET = libsolver.so
LIB_OBJECTS = solver_lib.o

all: $(LIB_TARGET)

$(LIB_TARGET): $(LIB_OBJECTS)
	$(CC) -shared -o $@ $^

solver_lib.o: solver_lib.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(LIB_TARGET) $(LIB_OBJECTS) *.so got.txt

.PHONY: all clean

run_remote_lib:
	cp ../local_lib/libgotoku.so .
	LD_PRELOAD=./libsolver.so LD_LIBRARY_PATH=. ./gotoku

get_got:
	python3 get_got.py

submit: all
	python3 submit.py libsolver.so
