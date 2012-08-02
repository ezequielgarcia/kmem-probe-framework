#!/bin/bash

# You must be root!

echo "Cleaning previous probefs"
umount ./probefs &> /dev/null
rm -f ./probefs.img

echo "Creating ext2 fs"
dd if=/dev/zero of=probefs.img bs=10M count=1 &>> create.log
mkfs.ext2 -i 1024 -F ./probefs.img &>> create.log
 
echo "Mounting"
mkdir -p ./probefs && mount -o loop probefs.img ./probefs

echo "Creating device nodes"
mkdir -p probefs/proc probefs/dev probefs/sys
source mkdevs.sh ./probefs/dev

echo "Installing busybox"
rsync -a ./busybox/_install/ ./probefs
cp -a ./busybox/examples/bootfloppy/etc ./probefs
chown -R root:root ./probefs

sync
umount ./probefs

echo "Done!"
