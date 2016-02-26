from usbscapy import *
from usbEmulator import usb_emulator

interface = USBInterfaceDescriptor(
        bInterfaceNumber       = 0,
        bAlternateSetting      = 0,
        bInterfaceClass        = 255,
        bInterfaceSubClass     = 0,
        bInterfaceProtocol     = 0,
        iInterface             = 0, # string index
        endpoints              = [],
)

config = USBConfigurationDescriptor(
        interfaces = [interface]
)

usbdev = USBDeviceDescriptor(
        bDeviceClass     = 0,
        bDeviceSubClass  = 0,
        bDeviceProtocol  = 0,
        bMaxPacketSize   = 64,
        idVendor         = 0x0763,
        idProduct        = 0x1002,
        configurations   = [ config ]
        )

usbdev.show()


emu = usb_emulator(["127.0.0.1", "1235"], 0)
emu.setup_payload(usbdev)
emu.execute()