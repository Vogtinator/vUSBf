from usbscapy import *

class USBDevice():
  name = "USBDevice"
  def __init__(self, device_descriptor):
    self.device_descriptor = device_descriptor
