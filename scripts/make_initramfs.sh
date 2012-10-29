if [ "$1" == "" ]; then
  echo "I need a directory to create an image"
  exit 1
fi

# This is the name of our image
src_name=`basename $1`
dst_name="${src_name}.cpio.gz"
echo "Creating initial ramfs at ${dst_name}"
cd ${src_name}/
find . | cpio -o --format=newc | gzip -9 > ../${dst_name}
cd ../

echo "Done!"
