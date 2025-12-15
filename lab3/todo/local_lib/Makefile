CC = gcc
CFLAGS = -Wall -fPIC

LIB_TARGET = libgotoku.so
LIB_OBJECTS = local_lib.o

all: $(LIB_TARGET)

$(LIB_TARGET): $(LIB_OBJECTS)
	$(CC) -shared -o $@ $^

local_lib.o: local_lib.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(LIB_TARGET) $(LIB_OBJECTS) *.so got.txt

.PHONY: all clean

run_local_lib: get_got
	cp libgotoku.so ../dummy/; \
	cd ../dummy; \
	make preload; \
	make clean

get_got: make_dummy
	python3 get_got.py

make_dummy:
	cd ../dummy; \
	make