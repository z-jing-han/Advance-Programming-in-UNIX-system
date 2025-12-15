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

run_dummy: all
	LD_LIBRARY_PATH=. ./gotoku.local

preload: all
	LD_PRELOAD=./libgotoku.so LD_LIBRARY_PATH=. ./gotoku.local
