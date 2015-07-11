
#!/usr/bin/env python
from scapy import *
from scapy.all import *

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


class Scapy80211():
    def  __init__(self,intf='wlan4',
      ssid='JimmyShoes',\
          source='00:C0:CA:57:23:4A',\
          bssid='00:11:22:33:44:55',srcip='10.10.10.10', mon = "wlan4"):
      self.rates = "\x03\x12\x96\x18\x24\x30\x48\x60"
      self.ssid    = ssid
      self.source  = source
      self.srcip   = srcip
      self.bssid   = bssid  
      self.intf    = intf
      self.intfmon = mon
      dst="c8:3a:35:c5:d3:ed"
      dst='ff:ff:ff:ff:ff:ff'
      # set Scapy conf.iface
      conf.iface = self.intfmon

    def ProbeReq(self,count=10,ssid='',dst='ff:ff:ff:ff:ff:ff'):
      if not ssid: ssid=self.ssid
      param = Dot11ProbeReq()
      essid = Dot11Elt(ID='SSID',info=ssid)
      rates  = Dot11Elt(ID='Rates',info=self.rates)
      dsset = Dot11Elt(ID='DSset',info='\x01')
      pkt = RadioTap()\
        /Dot11(type=0,subtype=4,addr1=dst,addr2=self.source,addr3=self.bssid)\
        /param/essid/rates/dsset

      print '[*] 802.11 Probe Request: SSID=[%s], count=%d' % (ssid,count)
      try:
        sendp(pkt,count=count,inter=0.1,verbose=0)
      except:
        raise

 
 #c8:3a:35:c5:d3:ed


    
# main routine
if __name__ == "__main__":
  import random
  val = "XXXX"
  sdot11 = Scapy80211(intf='wlan4', ssid="evil")       #bssid="c8:3a:35:c5:d3:ed"
  sdot11.ProbeReq()
