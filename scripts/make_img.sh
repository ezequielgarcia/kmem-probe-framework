#!/bin/bash

if [[ $UID -ne 0 ]]; then
  echo "$0 must be run as root!"
  exit 1
fi

if [ "$1" == "" ]; then
  echo "I need a directory to create an image"
  exit 1
fi

fs=ext2

# This is the name of our image
src_name=`basename $1`
dst_name="__"${src_name}
image_name=${src_name}".img"
image_size=`du -sm ${src_name} | awk '{print $1}'`

echo "Creating ${fs}"
dd if=/dev/zero of=${image_name} bs=1M count=512 &>> make_image.log
losetup /dev/loop0 ${image_name}
mkfs.${fs} /dev/loop0
 
echo "Mounting"
mkdir -p ./${dst_name} && mount -t ${fs} /dev/loop0 ./${dst_name}

echo "Syncing"
rsync -av ./${src_name}/* ./${dst_name} &>> make_image.log
umount ./${dst_name}
losetup -d /dev/loop0
chown zeta:zeta ${image_name}

echo "Done!"
