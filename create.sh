#!/bin/bash

if [[ $UID -ne 0 ]]; then
  echo "$0 must be run as root!"
  exit 1
fi

source clean.sh

echo "Creating ext2 fs"
dd if=/dev/zero of=probefs.img bs=10M count=1 &>> create.log
mkfs.ext2 -i 1024 -F ./probefs.img &>> create.log
 
echo "Mounting"
mkdir -p ./probefs && mount -o loop probefs.img ./probefs

echo "Creating device nodes"
mkdir -p probefs/proc probefs/dev probefs/sys
source mkdevs.sh ./probefs/dev

echo "Installing fs"
rsync -a ./busybox/_install/ ./probefs
cp -a ./templatefs/* ./probefs
chown -R root:root ./probefs

sync
umount ./probefs

echo "Done!"
