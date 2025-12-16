
obj-m     += cryptomod.o
ccflags-y += -DEXPORT_SYMTAB

all: my_test_crypto
	make -C ../dist/modulebuild M=$(PWD) modules

my_test_crypto:
	gcc -static -o my_test_crypto my_test_crypto.c

clean:
	make -C ../dist/modulebuild M=$(PWD) clean
	rm -f openssl_fun.jpg my_test_crypto *.o

install: all
	mkdir -p ../rootfs/modules
	openssl enc -aes-256-ecb -in fun.jpg.enc -out openssl_fun.jpg -K "e381aae38293e381a7e698a5e697a5e5bdb1e38284e381a3e3819fe381ae213f" -nosalt -d
	cp my_test_crypto ../../spec/test_crypto* cryptomod.ko fun.jpg.enc openssl_fun.jpg ../rootfs/modules
