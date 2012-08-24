#!/bin/bash

if [[ $UID -ne 0 ]]; then
  echo "$0 must be run as root!"
  exit 1
fi

# Mount probe fs and copy logs
mount -o loop probefs.img ./probefs
cp ./probefs/boot_kmem.log .
#cp ./probefs/boot_account .
umount ./probefs

# Post-process kmem events
cat boot_kmem.log | ./post-process/addr2sym.py -m linux/System.map | ./post-process/trace2account.py > boot_kmem_account.log
