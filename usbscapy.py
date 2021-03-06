"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'


from scapy.fields import *
from scapy.packet import *


#####################################
####### SCAPY EXTENSION STUFF #######
#####################################

# XLEShortField
class XLEShortField(LEShortField, XShortField):
    def i2repr(self, pkt, x):
        return XShortField.i2repr(self, pkt, x)


# XLEIntField
class XLEIntField(LEIntField, XIntField):
    def i2repr(self, pkt, x):
        return XIntField.i2repr(self, pkt, x)


####################################
####### REDIR SPECIFIC STUFF #######
####################################

usbredir_type_enum = {  # CONTROL PACKETS
                        0: "hello",
                        1: "device_connect",
                        2: "device_disconnect",
                        3: "reset",
                        4: "interface_info",
                        5: "ep_info",
                        6: "set_configuration",
                        7: "get_configuration",
                        8: "configuration_status",
                        9: "set_alt_setting",
                        10: "get_alt_setting",
                        11: "alt_setting_status",
                        12: "start_iso_stream",
                        13: "stop_iso_stream",
                        14: "iso_stream_status",
                        15: "start_interrupt_receiving",
                        16: "stop_interrupt_receiving",
                        17: "interrupt_receiving_status",
                        18: "alloc_bulk_streams",
                        19: "free_bulk_streams",
                        20: "bulk_streams_status",
                        21: "cancel_data_packet",
                        22: "filter_reject",
                        23: "filter_filter",
                        24: "device_disconnect_ack",  # DATA PACKETS
                        100: "data_control_packet",
                        101: "data_bulk_packet",
                        102: "data_iso_packet",
                        103: "data_interrupt_packet"}


usbredir_caps_enum = {
    # Supports USB 3 bulk streams
    0: "usb_redir_cap_bulk_streams",
    # The device_connect packet has the device_version_bcd field
    1: "usb_redir_cap_connect_device_version",
    # Supports usb_redir_filter_reject and usb_redir_filter_filter pkts
    2: "usb_redir_cap_filter",
    # Supports the usb_redir_device_disconnect_ack packet
    3: "usb_redir_cap_device_disconnect_ack",
    # The ep_info packet has the max_packet_size field
    4: "usb_redir_cap_ep_info_max_packet_size",
    # Supports 64 bits ids in usb_redir_header
    5: "usb_redir_cap_64bits_ids",
    # Supports 32 bits length in usb_redir_bulk_packet_header
    6: "usb_redir_cap_32bits_bulk_length",
    # Supports bulk receiving / buffered bulk input
    7: "usb_redir_cap_bulk_receiving",
};

#USB Device
#  Configurations
#    Interfaces
#      Endpoints


# DO NOT FUZZ THE FOLLOWING REDIR SPECIFIC PACKAGES! FUZZING WILL CAUSE IN QEMU CRASH!
class usbredirheader(Packet):
    name = "UsbredirPacket"
    fields_desc = [
                     LEIntEnumField("Htype", 0, usbredir_type_enum),
                     LEIntField("HLength", None),
                     LEIntField("Hid", 0)
                   ]

    def post_build(self, p, pay):
      p += pay
      if self.HLength == None:
        l = len(pay)
        p = p[:4] + struct.pack("I",l) + p[8:]
      return p

# Redir Packet No. 0 (redir hello)
class hello_redir_header(Packet):
    name = "Hello_Packet"
    fields_desc = [
                     StrFixedLenField("version", "", 64),
                     LEIntField("capabilites", 1)
                  ]

    def print_capabilities(self):
     for cap, capability_name in usbredir_caps_enum:
       if self.capabilities & (1 << (cap % 32)) > 0:
         print "Has capability: "  + capability_name

class hello_redir_header_host(Packet):
    name = "Hello_Packet_Host"
    fields_desc = [
                     StrLenField("version", "", length_from=56)
                  ]


# Redir Packet No. 1 (redir connect)
class connect_redir_header(Packet):
    name = "Connect_Packet"
    fields_desc = [ByteField("speed", 0),
                   XByteField("device_class", 0),
                   XByteField("device_subclass", 0),
                   XByteField("device_protocol", 0),
                   XLEShortField("vendor_id", 0),
                   XLEShortField("product_id", 0),
                   XLEShortField("device_version_bcd", 0)]


# Redir Packet No. 4 (interface info)   [SIZE 132 BYTES]
class if_info_redir_header(Packet):
    name = "Interface Info Packet"
    fields_desc = [LEIntField("interface_count", None),
                   FieldListField("interface", [0]*32, ByteField("Value", 0), length_from=lambda p: 32),
                   FieldListField("interface_class", [0]*32, ByteField("Value", 0), length_from=lambda p: 32),
                   FieldListField("interface_subclass", [0]*32, ByteField("Value", 0), length_from=lambda p: 32),
                   FieldListField("interface_protocol", [0]*32, ByteField("Value", 0), length_from=lambda p: 32)]


# Redir Packet No. 5 (endpoint info)    [SIZE 160 BYTES]
class ep_info_redir_header(Packet):
    name = "Endpoint Info Packet"
    fields_desc = [FieldListField("ep_type", [255]*32, ByteEnumField("type_value", 0, {0: "type_control",
                                                                                   1: "type_iso",
                                                                                   2: "type interrupt",
                                                                                   255: "type invalid", })
                                  , length_from=lambda p: 32),
                   FieldListField("interval", [0]*32, ByteField("Value", 0), length_from=lambda p: 32),
                   FieldListField("interface", [0]*32, ByteField("Value", 0), length_from=lambda p: 32),
                   FieldListField("max_packet_size", [0]*32, XLEShortField("Value", 0), length_from=lambda p: 32 * 2)]


# Redir Packet No. 100 (data control)   [SIZE 10 BYTES]
class data_control_redir_header(Packet):
    name = "Data_Control_Packet"
    fields_desc = [ByteField("endpoint", 0),
                   ByteField("request", 0),
                   ByteField("requesttype", 0),
                   ByteField("status", 0),
                   XLEShortField("value", 0),
                   LEShortField("index", 0),
                   LEShortField("length", 0)]


# Redir Packet No. 101 (data bulk)      [SIZE 8 BYTES]
class data_bulk_redir_header(Packet):
    name = "Data_Bulk_Packet"
    fields_desc = [ByteField("endpoint", 0),
                   ByteField("status", 0),
                   LEShortField("length", None),
                   LEIntField("stream_id", None),
                   LEShortField("length_high", None)]


# Redir Packet No. 102 (data iso)       [SIZE 4 BYTES]
class data_iso_redir_header(Packet):
    name = "Data_Iso_Packet"
    fields_desc = [ByteField("endpoint", 0),
                   ByteField("status", 0),
                   LEShortField("length", 0)]


# Redir Packet No. 103 (data interrupt) [SIZE 4 BYTES]
class data_interrupt_redir_header(Packet):
    name = "Data_Interrupt_Packet"
    fields_desc = [ByteField("endpoint", 0),
                   ByteField("status", 0),
                   LEShortField("length", 0)]

redir_specific_type = {
                       0: hello_redir_header,
                       1: connect_redir_header,
                       4: if_info_redir_header,
                       5:  ep_info_redir_header,
                       100: data_control_redir_header,
                       101: data_bulk_redir_header,
                       102: data_iso_redir_header,
                       103: data_interrupt_redir_header
                      }

for redir_type_id, redir_control_pkg in redir_specific_type.iteritems():
  bind_layers( usbredirheader, redir_control_pkg, Htype = redir_type_id)

##################################
####### USB SPECIFIC STUFF #######
####### ENUMARATION PHASE  #######
##################################

# USB Header (URB - replaced by usbredirheader)
class usb_header(Packet):
    name = "USB_Packet"
    fields_desc = [XLongField("id", 0xffff88003720d540),
                   ByteField("type", 43),
                   ByteField("transfer type", 2),
                   ByteField("endpoint", 80),
                   ByteField("device", 0),
                   LEShortField("bus_id", 0),
                   ByteField("device_setup_request", 0),
                   ByteField("data_present", 0),
                   LELongField("urb_sec", 0),
                   LEIntField("urb_usec", 0),
                   LEIntField("urb_status", 0),
                   LEIntField("urb_length", 0),
                   LEIntField("data_length", 0)]


# Generic USB Descriptor Header
class usb_generic_descriptor_header(Packet):
    name = "USB_GENERIC_DESCRIPTOR_HEADER"
    fields_desc = [ByteField("bLength", 0),
                   XByteField("bDescriptorType", 0x1)]

# USB Endpoint Descriptors
class USBEndpointDescriptor(Packet):
    name = "USBEndpointDescriptor"
    fields_desc = [
                   ByteField("bLength", 7),  # Size of Descriptor in Bytes (7 Bytes)
                   XByteField("bDescriptorType", 0x05),  # Configuration Descriptor (0x05)
                   XByteField("bEndpointAddress", None),  # Endpoint Address TODO!
                   XByteField("bmAttributes", None),  # TODO
                   LEShortField("wMaxPacketSize", None),
                   # Maximum Packet Size this endpoint is cabable of sending or recving
                   ByteField("bInterval", None)  # Interval for polling endpoint data transfer. Value in frame counts
    ]

# USB Interface_Descriptor
class USBInterfaceDescriptor(Packet):
    name = "USBInterfaceDescriptor"
    fields_desc = [
                   ByteField("bLength", 9),  # Size of Descriptor in Bytes (9 Bytes)
                   XByteField("bDescriptorType", 0x04),  # Configuration Descriptor (0x04)
                   ByteField("bInterfaceNumber",  0),  # Number of Interface
                   ByteField("bAlternateSetting", 0),  # Value used to select alternative setting
                   FieldLenField("bNumEndpoints", 0, fmt = "B", count_of="endpoints"),  # Number of Endpoints used for this interface
                   XByteField("bInterfaceClass",  0),  # Class Code [0x08: MASSSTORAGE, ...]
                   XByteField("bInterfaceSubClass", 0),  # Subclass Code
                   XByteField("bInterfaceProtocol", 0),  # Protocol Code
                   ByteField("iInterface", 0),  # Index of String Descriptor describing this interface
                   # Number of Endpoint items is given by bNumEndpoints
                   PacketListField("endpoints", [], USBEndpointDescriptor, \
                       count_from=lambda pkt: pkt.bNumEndpoints),
    ]


# USB Configuration Descriptor
class USBConfigurationDescriptor(Packet):
    name = "USBConfigurationDescriptor"
    fields_desc = [
                   ByteField("bLength", 9),  # Size of Descriptor in Bytes
                   XByteField("bDescriptorType", 0x02),  # Configuration Descriptor (0x02)
                   XLEShortField("wTotalLength", 0),  # Total length in bytes of data returned
                   FieldLenField("bNumInterfaces", 0, fmt = "B", count_of="interfaces"),  # Number of Interfaces
                   ByteField("bConfigurationValue", 1),  # Value to use as an argument to select this configuration
                   #iConfiguration is a index to a string descriptor describing the configuration in human readable form.
                   ByteField("iConfiguration", 0),  # Index of String Descriptor describing this configuration
                   FlagsField("bmAttributes", 0b11100000, 8, [
                       "Reserved_D0",  # Reserved Bit
                       "Reserved_D1",  # Reserved Bit
                       "Reserved_D2",  # Reserved Bit
                       "Reserved_D3",  # Reserved Bit
                       "Reserved_D4",  # Reserved Bit
                       "Remote_Wakeup",  # D5 Remote Wakeup
                       "Self_Powered",  # D6 Self Powered
                       "Reserved_D7",  # D7 Reserved: Must be 1 for USB1.1 and higher
                   ]),
                   ByteField("bMaxPower", 0x1),  # Maximum Power consumption in 2mA units
                   PacketListField("interfaces", [], USBInterfaceDescriptor, \
                        count_from=lambda pkt: pkt.bNumInterfaces),
    ]

# USB Device Descriptor Packet (DescriptorType 0x01)
class USBDeviceDescriptor(Packet):
    name = "USBDeviceDescriptor"
    fields_desc = [
                     ByteField("bLength", 18),
                     XByteField("bDescriptorType", 0x01),
                     XLEShortField("bcdUSB", 0x0),
                     XByteField("bDeviceClass", 0x1),
                     ByteField("bDeviceSubClass", 0),
                     ByteField("bDeviceProtocol", 0),
                     ByteField("bMaxPacketSize", 0),
                     XLEShortField("idVendor", 0x0),
                     XLEShortField("idProduct", 0x0),
                     XLEShortField("bcdDevice", 0x0),
                     #Index into a strings table
                     ByteField("iManufacturer", 0),
                     #Index into a strings table
                     ByteField("iProduct", 0),
                     #Index into a strings table
                     ByteField("iSerialNumber", 0),
                     FieldLenField("bNumConfigurations", None, fmt = "B", count_of="configurations"),
                     PacketListField("configurations", [], USBConfigurationDescriptor, \
                        count_from=lambda pkt: pkt.bNumConfigurations),
                   ]

class USBStringDescriptor_langid(Packet):
    name = "USBStringDescriptor_LangID"
    fields_desc = [ByteField("bLength", 0),
                   ByteField("bDescriptorType", 0),
                   FieldListField("wLANGID", 0x00, XLEShortField("Value", 1), count_from=lambda p: p.bLength)
    ]

class USBStringDescriptor(Packet):
    name = "USBStringDescriptor"
    fields_desc = [
                   ByteField("bLength", 0),
                   ByteField("bDescriptorType", 0),
                   FieldListField("UnicodeData", 0x00, XLEShortField("Char", 1), count_from=lambda p: p.bLength)
    ]


class USBHidDescriptor(Packet):
    name = "USBHidDescriptor"
    fields_desc = [ByteField("bLength", 0x9),
                   ByteField("bDescriptorType", 0x21),
                   XLEShortField("bcdHID", 0x0),
                   ByteField("bCountryCode", 0x00),
                   ByteField("bNumDescriptors", 0x00),  # WIEDERHOLT SICH IN RELATION ZUR ANZAHL DER DESCRIPTOREN
                   XByteField("bDescriptorType2", 0x22),  # 0x22 REPORT DESCRIPTOR  # 0x23 PYSICAL DESCRIPTOR
                   LEShortField("wDescriptorLength", 0x00)
  ]

class usb_hid_report_extension(Packet):
    name = "USB_HID_Report_Extension"
    fields_desc = [XByteField("bDescriptorType2", 0x22),  # 0x22 REPORT DESCRIPTOR # 0x23 PYSICAL DESCRIPTOR
                   LEShortField("wDescriptorLength", 0x00)
    ]


class usb_hid_report_descriptor(Packet):
    name = "USB_HID_Report_Descriptor"
    fields_desc = []


descriptor_types = {
                        0x01: USBDeviceDescriptor,
                        0x02: USBConfigurationDescriptor,
                        0x03: USBStringDescriptor,
                        0x04: USBInterfaceDescriptor,
                        0x05: USBEndpointDescriptor,
                        0x09: USBHidDescriptor
                        }


bind_layers(data_control_redir_header, usb_generic_descriptor_header, Htype = 100)

for descriptor_num, descriptor_t in descriptor_types.iteritems():
  bind_layers(usb_generic_descriptor_header, descriptor_t, \
                   bDescriptorType = descriptor_num)

## PROTOTYPE FOR USB_HUB_DESCRIPTOR ##
##
## typedef struct _USB_HUB_DESCRIPTOR {
##  UCHAR  bDescriptorLength;
##  UCHAR  bDescriptorType;
##  UCHAR  bNumberOfPorts;
##  USHORT wHubCharacteristics;
##  UCHAR  bPowerOnToPowerGood;
##  UCHAR  bHubControlCurrent;
##  UCHAR  bRemoveAndPowerMask[64];
## } USB_HUB_DESCRIPTOR, *PUSB_HUB_DESCRIPTOR;



##############################################
####### USB MASSSTORAGE SPECIFIC STUFF #######
######  SCSI                           #######
##############################################

# dCBWSignatur
dCBWSignature_magic_number = 0x43425355

#dCSWSignatur
dCSWSignature_magic_number = 0x53425355

# Command Generic Header
class massstorage_generic(Packet):
                name = "Massstorage_Generic"
                fields_desc = [ XLEIntField("dSignature", 0)]

# Command Block Wrapper  (CBW)          [SIZE: 12 Bytes]
class massstorage_cbw(Packet):
                                name = "Massstorage_CBW"
                                fields_desc = [ XLEIntField("dCBWSignature", 0),
                                IntField("dCBWTag", None),
                                XLEIntField("dCBWDataTransferLength", None),
                                ByteField("bmCBWFlags", None),
                                ByteField("bCBWLUN", None),
                                ByteField("bCBWCBLength", None)
                                ]

# Command Status Wrapper (CSW)
class massstorage_csw(Packet):
                name = "Massstorage_CSW"
                fields_desc = [ XLEIntField("dCSWSignature", 0),
                                IntField("dCSWTag", None),
                                XLEIntField("dCSWDataResidue", None),
                                                                ByteField("bCSWStatus", None)
                                ]

###################################
####### SCSI SPECIFIC STUFF #######
###################################

# SCSI_INQUIRY STRING LENGTH
SCSI_INQUIRY_VENDOR_ID_LENGTH = 8
SCSI_INQUIRY_PRODUCT_ID_LENGTH = 16
SCSI_INQUIRY_PRODUCT_REVISION_LEVEL_LENGTH = 4

# INQUIRY SCSI (SIZE: 36 Bytes)
class scsi_inquiry(Packet):
                name = "SCSI_Inquiry"
                fields_desc = [ ByteField("peripheral", None),
                                ByteField("RMB", None),
                                ByteField("version", None),
                                ByteField("?", None),
                                ByteField("additional_length", None),
                                ByteField("??", None),
                                ByteField("???", None),
                                ByteField("????", None),

                                StrFixedLenField("vendor_id", None, SCSI_INQUIRY_VENDOR_ID_LENGTH),
                                StrFixedLenField("product_id", None, SCSI_INQUIRY_PRODUCT_ID_LENGTH),
                                StrFixedLenField("product_revision_level", None, SCSI_INQUIRY_PRODUCT_REVISION_LEVEL_LENGTH)
                                ]

# Raw INQUIRY SCSI
class scsi_raw_inquiry(Packet):
                                name = "SCSI_Raw_Inquiry"
                                fields_desc = [ ByteField("peripheral", None),
                                                                ByteField("RMB", None),
                                                                ByteField("version", None),
                                                                ByteField("?", None),
                                                                ByteField("additional_length", None),
                                                                ByteField("??", None),
                                                                ByteField("???", None),
                                                                ByteField("????", None),
                                                                #PAYLOAD VENDOR ID[8] PRODUCT ID[16] PRODUCT REV[4]
                                                                ]

# READ CAPICITY SCSI
#class scsi_read_capicity(Packet):
#               name = "SCSI_READ_CAPICITY"
#               fields_desc = [ ByteField("opcode", 0x25),
#                               ByteField("reserved", None),
#                               XLEIntField("logical_block_adress", None),
#                               ShortField("reserverd", None),
#                               ByteField("reserverd", None),
#                               XByteField("control", None)
#               ]

# READ CAPICITY SCSI RESONSE
class scsi_read_capicity(Packet):
                name = "SCSI_READ_CAPICITY_RESPONSE"
                fields_desc = [ XLEIntField("returned_logic_block_addr", None),
                                                XLEIntField("block_length", None) ]

# MODE SELECT (6) SCSI RESPONSE
class scsi_mode_6(Packet):
                name = "SCSI_MODE_SELECT_(6)_RESPONSE"
                fields_desc = [ ByteField("mode_data_length", None),
                                ByteField("medium_field", None),
                                ByteField("dev-specific_parameter", None),
                                ByteField("block_desc_length", None) ]

# SCSI COMMAND LIST [OPCODE, NAME, SCAPYNAME]
SCSI_COMMAND_LIST = [   ['\x04', "FORMAT UNIT", None],
                                                ['\x12', "INQUIRY", scsi_inquiry],
                                                ['\x15', "MODE SELECT (6)", scsi_mode_6],
                                                ['\x55', "MODE SELECT (10)", None],
                                                ['\x1a', "MODE SENSE (6)", scsi_mode_6],
                                                ['\x5a', "MODE SENSE (10)", None],
                                                ['\x1e', "PREVENT ALLOW MEDIUM REMOVAL", None],
                                                ['\x08', "READ (6)", None],
                                                ['\x28', "READ (10)", None],
                                                ['\xa8', "READ (12)", None],
                                                ['\x25', "READ CAPACITY (10)", scsi_read_capicity],
                                                ['\x23', "READ FORMAT CAPACITY", None],
                                                ['\x43', "READ TOC/PMA/ATIP", None],
                                                ['\xa0', "REPORT LUNS", None],
                                                ['\x03', "REQUEST SENSE", None],
                                                ['\x1d', "SEND DIAGNOSITC", None],
                                                ['\x1b', "START STOP UNIT", None],
                                                ['\x35', "SYNCHRONIZE CACHE (10)", None],
                                                ['\x00', "TEST UNIT READY", None],
                                                ['\x2f', "VERIFY (10)", None],
                                                ['\x0a', "WRITE (6)", None],
                                                ['\x2a', "WRITE (10)", None],
                                                ['\xaa', "WRITE (12)", None]
                                ]

PROTO_IDS = {
    19: 'my_proto',
    # define all other proto ids
}

from scapy.layers.inet import *
class BaseProto(Packet):
    name = "BaseProto"
    fields_desc = [ # other fields omitted...
                    FieldLenField("len", 10, length_of="data", adjust = lambda pkt,x:x+6),
                    IntEnumField("protoId", 19, PROTO_IDS),
                    #StrLenField("data", "", length_from=lambda pkt: pkt.len-6), #<-- will be the next layer, extra data will show up as Raw or PADD
                   ]

def main():
    # my code here

  yo = hello_redir_header(version = "aaaaaaaaaaaaaa")
  bo = usbredirheader()
  blah = bo / yo
  blah.show()
  p = usbredirheader(str(blah))
  p.show()

  print "ep_info:"
  ep_info = usbredirheader() / ep_info_redir_header()
  ep_info.show2()

if __name__ == "__main__":
    main()

