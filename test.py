#!/usr/bin/env python
from scapy import *
from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

class Scapy80211():

    def  __init__(self,
                  intf='wlan4',
                  ssid='test',
                  source='00:c0:ca:57:23:4a',
                  bssid='00:11:22:33:44:55',
                  srcip='10.10.10.10'):

     # self.rates = "\x03\x12\x96\x18\x24\x30\x48\x60"
      self.rates = "\x02\x04\x0b\x16"

      self.ssid    = ssid
      self.source  = source
      self.srcip   = srcip
      self.bssid   = bssid
      self.intf    = intf
      self.intfmon = self.intf    

      # set Scapy conf.iface
      conf.iface = self.intfmon

      # create monitor interface using iw
      cmd = '/sbin/iw dev %s interface add %s type monitor >/dev/null 2>&1' \
        % (self.intf, self.intfmon)
      try:
        os.system(cmd)
      except:
        raise



  
    #'00:c0:ca:60:dc:bc'    Pineappple
    
    
    destination1 = '00:c0:ca:60:dc:bc'
    destination2 = 'ff:ff:ff:ff:ff:ff'


    def ProbeReq(self,count=10,ssid='',dst=destination2):
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
        # sendp() function will work at layer 2. works at layer 2
        sendp(pkt,count=count,inter=0.1,verbose=0)
      except:
        raise

# main routine
if __name__ == "__main__":
    print """
[*] 802.11 Probe Request Example
[*] 
[*] 
"""


channel = 0
for i in range(10):
  import os, sys
  if channel < 13:
    channel = channel + 1
 
  iface = "wlan4"
  os.system("ifconfig %s down" % iface)
  os.system("sudo iw dev " + iface + " set type monitor")
  os.system("ifconfig "+iface+" up")
  os.system("iw dev %s set channel %d" % (iface, channel))

  sdot11 = Scapy80211(intf='wlan4', ssid = "superman2")

  sdot11.ProbeReq()
  #sdot11.DNSQuery(ns='10.10.10.2')