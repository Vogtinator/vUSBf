from scapy.fields import *
from scapy.packet import *
from scapy.all import *
from lsusb_descriptor_parser import lsusbDescriptionParser
import config


#a = IP() / TCP()
#print a.proto
#a.show()
#

from usbscapy import *

if_info = usbredirheader() / if_info_redir_header()
if_info.show2()

data = lsusbDescriptionParser(config.DEV_DESC_FOLDER + "multi_flash.txt").parse()
payload = data[0]
if_info_packet = data[3]
ep_info_packet = data[4]
connect_packet = data[2]
