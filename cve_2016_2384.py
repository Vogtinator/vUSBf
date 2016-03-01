from usbscapy import *
from usbEmulator import usb_emulator
from usb_device import USBDevice

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

usbDevDescriptor = USBDeviceDescriptor(
        bDeviceClass     = 0,
        bDeviceSubClass  = 0,
        bDeviceProtocol  = 0,
        bMaxPacketSize   = 64,
        idVendor         = 0x0763,
        idProduct        = 0x1002,
        configurations   = [ config ]
        )


usbDev = USBDevice(usbDevDescriptor)

emu = usb_emulator(["127.0.0.1", 1235], 0)
emu.connect_device(usbDev)
