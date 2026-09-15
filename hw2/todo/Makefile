CC	= gcc
CXX	= g++
CXXFLAGS = -Wall -g
LDFLAGS = -lcapstone

PROGS	= sdb

all: $(PROGS)

sdb: sdb.o ptools.o
	$(CXX) -o $@ $^ $(LDFLAGS)

sdb.o: sdb.cpp ptools.h
	$(CXX) -c $(CXXFLAGS) $<

clean: clean_test_case
	rm -f *.o *~ $(PROGS)

copy_test_case:
	cp ../spec/hw2_demo_program/* ./

clean_test_case:
	rm -f anon hello hola ld-linux-x86-64.so.2 libc.so.6 mortis rana soyorin hola_link

test: sdb copy_test_case
	./run_tests.py check
