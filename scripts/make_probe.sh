#!/bin/bash

if [[ $UID -ne 0 ]]; then
  echo "$0 must be run as root!"
  exit 1
fi

export fs=ext2

source clean.sh

echo "Creating fs"
dd if=/dev/zero of=probefs.img bs=1M count=4 &>> create.log
losetup /dev/loop0 probefs.img
mkfs.${fs} /dev/loop0
 
echo "Mounting"
mkdir -p ./probefs && mount -t ${fs} /dev/loop0 ./probefs

echo "Creating device nodes"
mkdir -p probefs/proc probefs/dev probefs/sys
source mkdevs.sh ./probefs/dev

echo "Installing fs"
rsync -a ./busybox/_install/ ./probefs
cp -a ./templatefs/* ./probefs
chown -R root:root ./probefs

sync
umount ./probefs
losetup -d /dev/loop0
chown zeta:zeta probefs.img
gzip -f -9 probefs.img

echo "Done!"
