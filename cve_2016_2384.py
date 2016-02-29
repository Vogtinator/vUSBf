from usbscapy import *
from usbEmulator import usb_emulator
from usb_device import USBDevice
from lsusb_descriptor_parser import lsusbDescriptionParser

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

data = lsusbDescriptionParser("dev_desc/multi_flash.txt").parse()
payload = data[0]
if_info_packet = data[3]
ep_info_packet = data[4]
connect_packet = data[2]

Vusb = USBDevice(dev_descr)
emu = usb_redir_interface(["127.0.0.1", 1235], 0)
emu.connect_device(usb)

