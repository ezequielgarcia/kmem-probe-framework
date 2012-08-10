# Mount probe fs and copy logs
mount -o loop probefs.img ./probefs
cp ./probefs/boot_kmem.log .
cp ./probefs/boot_account.log .
umount ./probefs

# Post-process kmem events
cat boot_kmem.log | ./post-process/addr2sym.py -m linux/System.map | ./post-process/trace2account.py > boot_kmem_account.log
