#!/bin/bash

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
        make clean
	make
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
