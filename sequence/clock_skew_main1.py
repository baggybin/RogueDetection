from scapy.all import *
import sys
import datetime
import Queue
from multiprocessing import Process

class packet_sniffer(Process):
  def __init__(self,pass_queue):
    super(packet_sniffer,self).__init__()
    print 'Packet sniffer started'
    #self.target=self.monitor()
    self.queue=pass_queue
    self.device_dict={}
    self.not_an_ap={}
    print 'END'

  def run(self):
    sniff(iface="eth0",prn=self.PacketHandler)

  def PacketHandler(self,pkt):
    if(pkt.haslayer(ARP)):
      print pkt.src
    if pkt.haslayer(Dot11):
      sig_str = -(256-ord(pkt.notdecoded[-4:-3]))
      mac_addr=""
      ssid=""
      try:
        mac_addr=pkt.addr2
        ssid=pkt.info
      except:
        return
      if self.device_dict.has_key(pkt.addr2) and pkt.info!=self.device_dict[pkt.addr2]:
        output= "DIS MAC:%s RSSI:%s " %(pkt.addr2,sig_str)
        print output
        self.device_dict.pop(pkt.addr2)
        self.not_an_ap[pkt.addr2]=pkt.info
        self.queue.put(output)
      elif pkt.info=="" or pkt.info=="Broadcast":
        output= "DIS MAC:%s RSSI:%s " %(pkt.addr2,sig_str)
        print output
        self.queue.put(output)
      else:
        pot_mac=self.not_an_ap.get(pkt.addr2)
        if pot_mac == None:
          self.device_dict[pkt.addr2]=pkt.info
   