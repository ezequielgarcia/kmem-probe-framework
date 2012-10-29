fs=ext2
name=ext2_test

echo "Creating ${fs}"
dd if=/dev/zero of=${name}.img bs=1M count=512 &>> make_image.log
losetup /dev/loop0 ${name}.img
mkfs.${fs} /dev/loop0

mkdir -p ./${name} && mount -t ${fs} /dev/loop0 ./${name}

pushd ./${name}

for i in {1..3}; do
  mkdir -p $i
  if [ "$?" -ne "0" ]; then
    popd
    umount ./${name}
    return
  fi

  cd $i
  for j in {1..3}; do
    mkdir -p $j
    if [ "$?" -ne "0" ]; then
      popd
      umount ./${name}
      return
    fi

    cd $j
    for k in {1..100}; do
      dd if=/dev/urandom of=$k bs=256k count=1 &> /dev/null
      if [ "$?" -ne "0" ]; then
        popd
	echo "Out of room!"
        #tree ./${name}
        umount ./${name}
        return
      fi
    done
    cd ..

  done
  cd ..

done

popd
#tree ./${name}
umount ./${name}
chown zeta:zeta ${name}.img
