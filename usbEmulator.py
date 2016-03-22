"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

from usbparser import *
from lsusb_descriptor_parser import *
from emulator.enumeration_abortion import abortion_enumeration
from emulator.enumeration import enumeration
from emulator.hid import hid
from fuzzer import fuzzer
import config


class usb_emulator:
    port = 0
    ip = ""
    unix_socket = ""

    # payload specific member variables
    payload = []
    hello_packet = ""
    connect_packet = None
    if_info_packet = None
    ep_info_packet = None
    enum_emulator = None

    # address_type:
    # 0:	[IP, TCP]
    # 1:	[Unix-Socket]
    def __init__(self, victim_address, address_type):

        if victim_address is None or address_type is None:
            raise Exception("Victim address errror")

        if address_type == 0:
            if len(victim_address) != 2:
                raise Exception("Victim address error - expected format is [IP, PORT]")
            else:
                if victim_address[0] is None or victim_address[1] is None:
                    raise Exception("Victim address error - expected format is [IP, PORT]")
            self.ip = victim_address[0]
            self.port = victim_address[1]

        elif address_type == 1:
            self.unix_socket = victim_address
        else:
            raise Exception("Unknown address type")

        self.hello_packet = config.USB_REDIR_HELLO_PACKET

    def setup_payload(self, payload):

        data = lsusbDescriptionParser(config.DEV_DESC_FOLDER + payload.get_option("descriptor")).parse()
        self.payload = data[0]
        self.if_info_packet = data[3]
        self.ep_info_packet = data[4]
        self.connect_packet = data[2]

        fuzzer_obj = fuzzer(payload)
        fuzzer_obj.set_descriptor(self.payload)

        emulator = payload.get_option("emulator")
        if emulator == "enumeration":
            self.enum_emulator = enumeration(fuzzer_obj)
        elif emulator == "enumeration_abortion":
            self.enum_emulator = abortion_enumeration(fuzzer_obj)
        elif emulator == "hid":
            self.enum_emulator = hid(fuzzer_obj)
        else:
            raise Exception("Unknown emulator")


    def handle_control_packet(self, raw_data, usbDev):
      usb_redir_packet = usbredirheader(raw_data)

      # Handle control packets only
      if usb_redir_packet.Htype != 100:
        return None

      if usb_redir_packet.endpoint != 0x80:
        return usb_redir_packet

      descriptor_request = usb_redir_packet.value >> (8)
      descriptor_num = usb_redir_packet.value % 256
      request = usb_redir_packet.request

      print "descriptor_request: "  + str(descriptor_request)
      if descriptor_request == 0x01:
        r = str(usbDev.device_descriptor)
        dd = USBDeviceDescriptor(r)
        dd.configurations = []
        dd.bNumConfigurations = len(usbDev.device_descriptor.configurations)


        USBDeviceDescriptor(str(dd)).show()

        pkt = usb_redir_packet / dd
        pkt.HLength = len(str(dd)) + 10
        pkt.length = len(str(dd))
        pkt.status = 0
        return pkt
      # configuration_descriptor
      elif descriptor_request == 0x02:
        if usb_redir_packet.length > 9:
          print "We were expecting the full USBDeviceDescriptor"
        config_desc = usbDev.device_descriptor.configurations[descriptor_num]
        config_desc.interfaces = []
        config_desc.bNumInterfaces = 1
        print "USB Config desc: "
        USBConfigurationDescriptor(str(config_desc)).show()
        pkt = usb_redir_packet / config_desc
        pkt.HLength = len(str(config_desc)) + 10
        pkt.status  =  0
        pkt.length  = len(str(config_desc))
        print "Requested configuration number: "  + str(descriptor_num)
        return pkt
      elif descriptor_request == 0x03:
        return usb_redir_packet / USBStringDescriptor('\x04\x03\x09\x04')


    def connect_device(self, usbDev):
        connection_to_victim = self.__connect_to_server()
        if connection_to_victim is None:
            print "Unable to connect to victim..."
            return False

        #connection_to_victim.settimeout(config.CONNECTION_TO_VICTIM_TIMEOUT)

        hello_packet = self.__recv_data(80, connection_to_victim)
        usbredirheader(hello_packet).show()
        self.__print_data(hello_packet, True)
        self.__print_data(self.__send_data(self.__get_hello_packet(), connection_to_victim), False)

        device_descriptor = usbDev.device_descriptor

        ep_info_header = ep_info_redir_header()
        interface_info_redir = if_info_redir_header()
        connect_redir        = connect_redir_header()

        connect_redir.speed           = 2
        connect_redir.device_class    = device_descriptor.bDeviceClass
        connect_redir.device_subclass = device_descriptor.bDeviceSubClass
        connect_redir.device_protocol = device_descriptor.bDeviceProtocol
        connect_redir.vendor_id       = device_descriptor.idVendor
        connect_redir.product_id      = device_descriptor.bcdDevice

        ep_count = 0
        for config in device_descriptor.configurations:
          interface_info_redir.interface_count = len(config.interfaces)
          print "Interface count : "  + str(interface_info_redir.interface_count)
          for index, interface in enumerate(config.interfaces):

            interface_info_redir.interface[index] = interface.bInterfaceNumber
            interface_info_redir.interface_class[index] = interface.bInterfaceClass
            interface_info_redir.interface_subclass[index] = interface.bInterfaceSubClass
            interface_info_redir.interface_protocol[index] = interface.bInterfaceProtocol

            for endpoint in interface.endpoints:
              ep_count += 1
              ep_info_header.ep_type[ep_count]   = endpoint.bmAttributes % 4
              ep_info_header.interval[ep_count]  = endpoint.bInterval
              ep_info_header.interface[ep_count] = interface.bInterfaceNumber
              ep_info_header.max_packet_size[ep_count] = endpoint.wMaxPacketSize


        #Default control endpoints
        ep_info_header.ep_type[0] = 0  #type_control
        ep_info_header.ep_type[16] = 0  #type_control


        #usbredir procotol specifies that we must send the usb_redir_ep_info
        # then usb_redir_interface_info
        # then we can send usb_redir_device_connect_info

        ep_info_data = str(usbredirheader() / ep_info_redir_header())
        self.__print_data(self.__send_data(ep_info_data, connection_to_victim), False)

        interface_info_data = str(usbredirheader() / interface_info_redir)
        self.__print_data(self.__send_data(interface_info_data, connection_to_victim), False)

        connect_device_data = str(usbredirheader() / connect_redir)
        self.__print_data(self.__send_data(connect_device_data, connection_to_victim), False)
        self.redir_loop(connection_to_victim, usbDev)

    def execute(self):
        connection_to_victim = self.__connect_to_server()
        if connection_to_victim is None:
            print "Unable to connect to victim..."
            return False
        r_value = self.__connection_loop(connection_to_victim)
        return r_value

    def __get_hello_packet(self):
        pkt = usbredirheader()
        pkt.Htype = 0
        pkt.HLength = 68
        pkt.Hid = 0
        pkt = pkt / Raw(self.hello_packet)
        return str(pkt)

    def __get_connect_packet(self):
        pkt = usbredirheader()
        pkt.Htype = 1
        pkt.HLength = 10
        pkt.Hid = 0
        pkt = pkt / Raw(str(self.connect_packet))
        return str(pkt)

    def __get_if_info_packet(self):
        pkt = usbredirheader()
        pkt.Htype = 4
        pkt.HLength = 132
        pkt.Hid = 0
        pkt = pkt / Raw(str(self.if_info_packet))
        return str(pkt)

    def __get_ep_info_packet(self):
        pkt = usVbredirheader()
        pkt.Htype = 5
        pkt.HLength = 160
        pkt.Hid = 0
        pkt = pkt / Raw(str(self.ep_info_packet))
        return str(pkt)

    def __get_reset_packet(self):
        pkt = usbredirheader()
        pkt.Htype = 3
        pkt.HLength = 0
        pkt.Hid = 0
        return str(pkt)

    def redir_loop(self, connection_to_victim, usbDev):
        for _ in range(config.MAX_PACKETS):
            new_packet = usbredirheader(self.__recv_data_dont_print(12, connection_to_victim))
            if new_packet.Htype == -1:
                return True
            raw_data = self.__recv_data_dont_print(new_packet.HLength, connection_to_victim)
            raw_data = str(new_packet) + raw_data
            new_packet = usbredir_parser(raw_data).getScapyPacket()
            self.handle_redir_packet(new_packet, connection_to_victim, usbDev)


    def handle_redir_packet(self, new_packet, connection_to_victim, usbDev):
       raw_data = str(new_packet)
       # hello packet
       if new_packet.Htype == 0:
           self.__print_data(str(new_packet), True)
           self.__print_data(self.__send_data(str(new_packet), connection_to_victim), False)

       # reset packet
       elif new_packet.Htype == 3:
           self.__print_data(str(new_packet), True)
           self.__print_data(self.__send_data(self.__get_reset_packet(), connection_to_victim), False)

       # set_configuration packet
       elif new_packet.Htype == 6:
           self.__print_data(str(new_packet), True)
           new_packet.Htype = 8
           new_packet.HLength = new_packet.HLength + 1
           new_packet.payload = Raw('\x00' + str(new_packet.payload))
           self.__print_data(self.__send_data(str(new_packet), connection_to_victim), False)
           #connection_to_victim.settimeout(0.5)

       # start_interrupt_receiving packet
       elif new_packet.Htype == 15:
           self.__print_data(str(new_packet), True)
           new_packet.Htype = 17
           new_packet.HLength = new_packet.HLength + 1
           new_packet.payload = Raw('\x00' + str(new_packet.payload))
           self.__print_data(self.__send_data(str(new_packet), connection_to_victim), False)
           return True

       # cancel_data_packet packet
       elif new_packet.Htype == 21:
           return True

       # data_control_packet packet
       elif new_packet.Htype == 100:
           # recv request
           self.__print_data(raw_data, True)
           # send response
           response = str(self.handle_control_packet(str(new_packet), usbDev))
           self.__print_data(self.__send_data(response, connection_to_victim), False)

       # data_bulk_packet packet
       elif new_packet.Htype == 101:
           self.__send_data(response, connection_to_victim)

       # data_interrupt_packet packet
       elif new_packet.Htype == 103:
           new_packet.HLength = 4
           Raw(raw_data).show()
           interrupt_payload = data_interrupt_redir_header(raw_data[12:])
           Raw(str(new_packet) + str(interrupt_payload)).show()
           interrupt_payload.status = 0
           interrupt_payload.load = None
           Raw(str(new_packet) + str(interrupt_payload)).show()
           self.__send_data(str(new_packet) + str(interrupt_payload), connection_to_victim)
       else:
           return True

    def __connection_loop(self, connection_to_victim):

        connection_to_victim.settimeout(config.CONNECTION_TO_VICTIM_TIMEOUT)
        try:
            hello_packet = self.__recv_data(80, connection_to_victim)
            usbredirheader(hello_packet).show()
            self.__print_data(hello_packet, True)
            self.__print_data(self.__send_data(self.__get_hello_packet(), connection_to_victim), False)
            self.__print_data(self.__send_data(self.__get_if_info_packet(), connection_to_victim), False)
            self.__print_data(self.__send_data(self.__get_ep_info_packet(), connection_to_victim), False)
            self.__print_data(self.__send_data(self.__get_connect_packet(), connection_to_victim), False)
        except:
            return False

        self.redir_loop(connection_to_victim, self.enum_emulator.get_response, usbDev)

        return True

    def __print_data(self, data, recv):
        if config.VERBOSE_LEVEL >= config.VERBOSE_LEVEL_PRINT_RECV_DATA:
            print config.DELIMITER
            if recv:
                print "RECV: Type ",
            else:
                print "SEND: Type ",

            try:
                print usbredir_type_enum[usbredirheader(data).Htype]
            except:
                print usbredirheader(data).Htype
            try:
                usbredirheader(data).show()
            except:
                Raw(data).show()
            print ""

    # if verbose level 3 or higher print packet content
    def __recv_data(self, length, connection_to_victim):
        try:
            data = connection_to_victim.recv(length)
            if(len(data) != length):
              print "We received an amount of data we didn't expect"
            return data
        except Exception as e:
            print e.message  + " during receiving data"
            return ""

    def __recv_data_dont_print(self, length, connection_to_victim):
        return connection_to_victim.recv(length)


    def __send_data(self, data, connection_to_victim):
        try:
            connection_to_victim.send(data)
            return data
        except:
            return ""

    def __print_error(self, msg):
        if config.VERBOSE_LEVEL >= config.VERBOSE_LEVEL_PRINT_ERROR_MESSAGES:
            print "ERROR:\t" + msg

    def __connect_to_server(self):
        num_of_tries = 0
        connection_to_victim = None
        while True:
            try:
                if self.unix_socket == "":
                    print "Connecting to victim on TCP socket "  + str(self.ip)  + ":" + str(self.port)
                    connection_to_victim = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    connection_to_victim.settimeout(config.TCP_SOCKET_TIMEOUT)
                    connection_to_victim.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    connection_to_victim.connect((self.ip, self.port))
                else:
                    connection_to_victim = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    connection_to_victim.settimeout(config.UNIX_SOCKET_TIMEOUT)
                    connection_to_victim.connect(self.unix_socket)
                break
            except:
                num_of_tries += 1
                if config.NUMBER_OF_RECONNECTS == num_of_tries:
                    time.sleep(config.TIME_BETWEEN_RECONNECTS)
                    return None
        return connection_to_victim
