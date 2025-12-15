CC	= gcc
CXX	= g++
CFLAGS	= -Wall -g
LDFLAGS = -lcapstone

PROGS	= sdb

all: $(PROGS)

sdb: sdb.o ptools.o
	$(CXX) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) -c $(CFLAGS) $<

clean: clean_test_case
	rm -f *.o *~ $(PROGS)

copy_test_case:
	cp ../spec/hw2_demo_program/* ./

clean_test_case:
	rm -f anon hello hola ld-linux-x86-64.so.2 libc.so.6 mortis rana soyorin

ex1: sdb
	printf "si\nload ./hello\nsi\nsi\ncont\n" | ./sdb
	printf "si\nsi\ncont\n" | ./sdb ./hola

ex2: sdb
	printf "break 0x401626\nbreakrva 17e6\ninfo break\nsi\nsi\ncont\ninfo reg\ncont\n" | ./sdb ./hello

ex3: sdb
	printf "break 401798\ncont\ncont\npatch 40179e 7f\ninfo break\ndelete 0\npatch deadbeef 1337\nbreak deadbeef\nbreakrva deadbeef\ncont\n" | ./sdb ./rana

ex4: sdb
	printf "break 0x40179F\nbreak 4017B4\ncont\nsyscall\nsyscall\nsyscall\nsyscall\nsyscall\n" | ./sdb ./hello

extra_example: sdb
	printf "break 401828\ncont\nsi\nbreak 0x700000000ffa\ncont\nsi\nsi\nsi\ncont\n" | ./sdb ./anon

h1: sdb
	printf "info reg\nbreak 401210\nbreak 401214\ncont\nsi\ncont\nsi\npatch 0x4011d8 580f05\npatch 0x4011d4 31ff6a3c\nsi\ncont\n" | ./sdb ./mortis

h2: sdb
	printf "info reg\nbreakrva 8943\nbreakrva 8947\ncont\nsyscall\nsyscall\nsyscall\ncont\ninfo break\ndelete 1\ninfo break\ncont\ndelete 0\ninfo break\ncont\n" | ./sdb ./soyorin

h3: sdb
	printf "break 40179e\ncont\nbreak 4017a0\npatch 40179e 7f1148\ninfo break\ncont\npatch 40179e 7e\ndelete 0\ncont\ndelete 1\ncont\n" | ./sdb ./rana

h4: sdb
	printf "breakrva 1828\ncont\nbreak 700000000000\ncont\npatch 0x700000000fc9 6844200b018134240101010148b875616e67204c4f565048b850726f662e206368504889e66a015f6a135a6a01580f0531ff6a3c58\nsyscall\nsyscall\nsi\npatch 0x700000000ffe 0f05\nbreak 700000000ffd\ncont\ndelete 2\ncont\n" | ./sdb ./anon

run_all_ex: copy_test_case extra_example ex1 ex2 ex3 ex4 h1 h2 h3 h4
