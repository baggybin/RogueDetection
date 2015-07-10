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
                  source='00:C0:CA:57:23:4A',
                  bssid='00:11:22:33:44:55',
                  srcip='10.10.10.10'):

      self.rates = "\x03\x12\x96\x18\x24\x30\x48\x60"
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


    #def Beacon(self,count=1,ssid='',dst='ff:ff:ff:ff:ff:ff'):
    #  if not ssid: ssid=self.ssid
    #  beacon = Dot11Beacon(cap=0x2104)
    #  essid  = Dot11Elt(ID='SSID',info=ssid)
    #  rates  = Dot11Elt(ID='Rates',info=self.rates)
    #  dsset  = Dot11Elt(ID='DSset',info='\x01')
    #  tim    = Dot11Elt(ID='TIM',info='\x00\x01\x00\x00')
    #  pkt = RadioTap()\
    #    /Dot11(type=0,subtype=8,addr1=dst,addr2=self.source,addr3=self.bssid)\
    #    /beacon/essid/rates/dsset/tim
    #
    #  print '[*] 802.11 Beacon: SSID=[%s], count=%d' % (ssid,count)
    #  try:
    #    sendp(pkt,iface=self.intfmon,count=count,inter=0.1,verbose=0)
    #  except:
    #    raise


  
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
      
      
      
    def ProbeReq2(self,count=10,ssid='',dst=destination2):
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
    channel = 1
    
  channel +=1
  iface = "wlan4"
  os.system("ifconfig %s down" % iface)
  os.system("sudo iw dev " + iface + " set type monitor")
  os.system("ifconfig "+iface+" up")
  os.system("iw dev %s set channel %d" % (iface, channel))
  

  sdot11 = Scapy80211(intf='wlan4', ssid="pine")
  #sdot11.Beacon()
  sdot11.ProbeReq()
  
  #
  #pkt = RadioTap()\
  #      /Dot11(subtype=4L,type=Management,addr1=dst,addr2=self.source,addr3=self.bssid)\
  #      /beacon/essid/rates/dsset/tim
  #
  #
  #<Dot11  subtype=4L type=Management proto=0L FCfield= ID=0 addr1=ff:ff:ff:ff:ff:ff addr2=7c:d1:c3:f7:58:81 addr3=ff:ff:ff:ff:ff:ff SC=56976 addr4=None |<Dot11ProbeReq  |<Dot11Elt  ID=SSID len=4 info='pine' |<Dot11Elt  ID=Rates len=4 info='\x02\x04\x0b\x16' |<Dot11Elt  ID=ESRates len=8 info='\x0c\x12\x18$0H`l' |<Dot11Elt  ID=DSset len=1 info='\x01' |<Dot11Elt  ID=45 len=26 info=',H\x17\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' |<Dot11Elt  ID=127 len=8 info='\x04\x00\x00\x00\x00\x00\x00@' |<Dot11Elt  ID=165 len=220 info='\xe5\xd3' |>>>>>>>>>>
  #
  #
  
  
  

