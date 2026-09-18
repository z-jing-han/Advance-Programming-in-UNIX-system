
obj-m     += cryptomod.o
ccflags-y += -DEXPORT_SYMTAB

all: padding_test multi_test share_fd_test
	make -C ../dist/modulebuild M=$(PWD) modules

padding_test:
	gcc -static -o padding_test padding_test.c

multi_test:
	gcc -static -o multi_test multi_test.c

share_fd_test:
	gcc -static -pthread -o share_fd_test share_fd_test.c

clean:
	make -C ../dist/modulebuild M=$(PWD) clean
	rm -f openssl_fun.jpg padding_test multi_test share_fd_test *.o

install: all
	mkdir -p ../rootfs/modules
	openssl enc -aes-256-ecb -in fun.jpg.enc -out openssl_fun.jpg -K "e381aae38293e381a7e698a5e697a5e5bdb1e38284e381a3e3819fe381ae213f" -nosalt -d
	cp padding_test multi_test share_fd_test ../../spec/test_crypto* cryptomod.ko fun.jpg.enc openssl_fun.jpg ../rootfs/modules
