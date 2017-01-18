from usbscapy import *
from usbEmulator import usb_emulator
from usb_device import USBDevice
from lsusb_descriptor_parser import lsusbDescriptionParser
import socket

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

# create an INET, STREAMing socket
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# bind the socket to a public host, and a well-known port
serversocket.bind(("10.160.67.51", 1024))
# become a server socket
serversocket.listen(5)

emu = usb_emulator(serversocket.accept()[0], 1)
emu.connect_device(usbDev)

data = lsusbDescriptionParser("dev_desc/multi_flash.txt").parse()
payload = data[0]
if_info_packet = data[3]
ep_info_packet = data[4]
connect_packet = data[2]
