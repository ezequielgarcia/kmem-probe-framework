qemu-system-i386 \
	-kernel bzImage \
	-hda probefs.img \
	-append "debug ignore_level root=/dev/sda trace_event=kmem:kmalloc,kmem:kmalloc_node,kmem:kfree" \
	-serial telnet:localhost:2222,server,nowait
