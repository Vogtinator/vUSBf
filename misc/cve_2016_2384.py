from usbscapy import *

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