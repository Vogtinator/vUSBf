HARDDRIVE_IMAGE=/opt/wheezy.img
QEMU_PATH=qemu-system-x86_64
KERNEL_PATH=/opt/linux/arch/x86/boot/bzImage
USB_HOST_ADDR=0.0.0.0
USB_PORT_ADDR=1235


$QEMU_PATH \
              -nographic \
              --enable-kvm \
              -m 2048 \
              -net nic \
              -net user,host=10.0.2.10,hostfwd=tcp::23505-:22 \
              -device nec-usb-xhci \
              -serial mon:stdio \
              -device usb-redir,chardev=usbchardev,debug=0 \
              -chardev socket,server,id=usbchardev,port=$USB_PORT_ADDR,host=$USB_HOST_ADDR,nodelay,nowait \
              -kernel $KERNEL_PATH \
              -hda $HARDDRIVE_IMAGE \
              -append root=/dev/sda
