#qemu-system-i386 -kernel bzImage -hda probefs.img -append "root=/dev/sda console=ttyS0,38400" -serial file:serial.out
qemu-system-i386 -kernel bzImage -hda probefs.img -append "root=/dev/sda"

