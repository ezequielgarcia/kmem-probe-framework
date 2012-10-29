#!/bin/bash

if [[ $UID -ne 0 ]]; then
  echo "$0 must be run as root!"
  exit 1
fi

# Mount probe fs and copy logs
mount -o loop angstrom_sysvinit.img ./__angstrom_sysvinit
cp ./__angstrom_sysvinit/kmem.log .
#cp ./__angstrom_sysvinit/boot_account.log .
umount ./__angstrom_sysvinit


#mount -o loop probefs.img ./__probefs
#cp ./__probefs/kmem.log .
#umount ./__probefs

chown zeta:zeta kmem.log
