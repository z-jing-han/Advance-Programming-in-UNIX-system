# Lab 2 have fun with kernel module

You need to create a Kernel Module.
It's relatively complex, so there’s a pre-lab practice beforehand, which is basically about:
1. How to launch a kernel
2. How to insert our program into the kernel

||It’s complicated—I didn’t really understand it either||


## Pre-lab

The Dockerfile does not contain `cpio` and `qemu`, so we need to install it (or you can modify the Dockerfile)

```.bash
sudo apt install qemu-system-x86 cpio
```

Assume the module name is `cryptomod`

### WSL
Follow the later part of instruction in pre-lab, cross-complie is needed.

First setting
```.bash
# In Host Machine (WSL)
cd todo/cryptomod
cp ../../spec/Pre-Lab-Announcement/*.tbz ./
tar -xvf crossbuild.tbz
cd crossbuild
chmod +x build.sh
# Change Image Name if you want
./build.sh
```

```.bash
# In up-runtime Dokcer
cd todo/cryptomod
cp ../../spec/Pre-Lab-Announcement/*.tbz ./
tar -xvf dist-6.6.17.tbz
chmod +x qemu.sh
```

Then, each time to complie
```.bash
# In Host Machine (WSL), Ensure in the parent of dist/ and cryptomod/
# And if you change the Image Name, you need to replace it at upclass/crossbuild
docker run -it --rm --user "$UID:$GID" -v "`pwd`:/build" -w /build -e PS1="buildenv:\w\$ " upclass/crossbuild /bin/bash --norc
# Enter cross-complie docker
cd crypto
make clean
make ARCH=x86 CROSS_COMPILE=x86_64-linux-gnu-
exit
```

```.bash
# In up-runtime Docker
./archive_into_kernel.sh cryptomod/
./qemu.sh
```

### VMWare + Ubuntu

```.bash
cd todo/cryptomod
cp ../../spec/Pre-Lab-Announcement/dist-6.6.17.tbz ./
tar -xvf dist-6.6.17.tbz
rm -f *.tbz
chmod +x qemu.sh
./archive_into_kernel.sh cryptomod/
./qemu.sh
```

## Goal

The kernel module includes:

1. `write`  — input into the kernel
2. `read`  — output from the kernels
3. `ioctl` — control I/O

Follow the spec to implement these features.

## Todo

The code I wrote is under `312552056_lab02/`.
I copied a version into the `todo/` directory.

`archive_into_kernel.sh` is a script I wrote myself. After compiling, basically only the `.ko` file is needed to be packaged into the kernel along with `qemu.sh`.

`cryptomod.c`
You can refer to the comments. Besides the spec-required functions, the rest should be the same as the starter code.

One thing to pay attention to is the `DEC` + `ADV` scenario.
In this case, you must always keep one block in the buffer before receiving the final block; otherwise, it won’t be able to decrypt the padding properly.

||In theory, for side-channel issues with multi-threading, just locking everything with mutex should work. But in my case, if I don’t add `printk` at the beginning and end of a function, it causes multithreading issues—so there’s probably a bug||

25/10/8: Fix the error of multi-thread test case and the kernel panic cause by large kernel buffer size (vi `kmalloc`) => use the `kfree()` care, care very carefully, please
