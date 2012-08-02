qemu-system-i386 \
	-kernel bzImage \
	-hda probefs.img \
	-append "root=/dev/sda" \
	-serial telnet:localhost:2222,server,nowait
