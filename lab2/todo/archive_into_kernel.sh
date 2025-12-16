#!/bin/bash

IS_WSL=0
if grep -qi microsoft /proc/version; then
    IS_WSL=1
    echo "[Info] Detected WSL environment."
else
    echo "[Info] Detected Native Linux environment (VMWare/DualBoot)."
fi

if [ -z "$1" ]; then
    echo "Error: Missing module directory argument."
    echo "Usage: $0 <module_directory>"
    echo "Skipping module build..."
else
    MODULE_DIR="$1"
    
    if [ ! -d "$MODULE_DIR" ]; then
        echo "Error: Directory '$MODULE_DIR' does not exist."
        echo "Skipping module build..."
    else
        cd "$MODULE_DIR"

        if [ "$IS_WSL" -eq 1 ]; then
            echo "[WSL] Skipping 'make clean' and 'make' (Assuming Cross-Compile is done via Docker)."
        else
            echo "[Native] Running 'make clean' and 'make'..."
            make clean
            make
        fi

        make install
        cd ..
    fi
fi

mkdir -p rootfs
cd rootfs
bzip2 -dc ../dist/rootfs.cpio.bz2 | cpio -idv
cd ..
sudo chown root:root -R rootfs
cd rootfs
find . | cpio -o -H newc | bzip2 > ../dist/rootfs.cpio.bz2
cd ..
sudo rm -rf rootfs
