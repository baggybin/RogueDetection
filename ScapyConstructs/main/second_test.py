#!/usr/bin/env python

'''
Python imports
'''
from scapy import *
from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

'''
ProbeTesting Class
has inital parameters set
for monitor interface
source mac
BSSID - Layer2 Idendifier
Destination address
and the Source IP addresss
'''
class probeTesing():
   #Python Constructor
   #inital paramaters that are set, but can be overwritten on method call
   '''
   *Source IP of this Station
   *holds BSSID (mac) of AP
   *Source, Destination addresss are only of intererest here.
    as we are not atttemprong to route through a distribution system
    '''
   def __init__(self,
                   intf='wlan4',
                   ssid='test',
                   source='00:C0:CA:57:23:4A',
                   bssid='ff:ff:ff:ff:ff:ff',
                   dst='ff:ff:ff:ff:ff:ff',
                   srcip='10.10.10.10'):

      ## supported rated set in hex
      self.rates = "\x03\x12\x96\x18\x24\x30\x48\x60"
      self.ssid    = ssid
      self.source  = source
      self.srcip   = srcip
      self.bssid   = bssid
      self.intf    = intf
      self.dest = dst
      self.intfmon = self.intf    

      ## set Scapy conf.iface
      conf.iface = self.intfmon

      # creating monitor interface using iw
      # command is passs
      cmd = '/sbin/iw dev %s interface add %s type monitor >/dev/null 2>&1' \
        % (self.intf, self.intfmon)
      try:
        os.system(cmd)
      except:
        raise
    

#Method to generate the Probe Request
#It will send itself 10 times to either broadcast "" nulll ssid or specified
#destination is broadcast as default
   def ProbeReq(self,count=10,ssid='',dst="ff:ff:ff:ff:ff:ff"):
      if not ssid: 
      	ssid=self.ssid
      #create probeRequest Object
      ProbeReq = Dot11ProbeReq()
      #Esssid object with the target name
      essid = Dot11Elt(ID='SSID',info=ssid)
      #Suppported Rates Object
      rates = Dot11Elt(ID='Rates',info=self.rates)
      # Frame set to be leaving the distribution system
      dsset = Dot11Elt(ID='DSset',info='\x01')
      '''
      create
      radiotap header
      '''
      #Here the final 802.11 probe Request frame is construcgtedec by concatantating eacg object to ther next
      pkt = RadioTap()\
        /Dot11(type=0,subtype=4,addr1=dst,addr2=self.source,addr3=self.bssid)\
        /ProbeReq/essid/rates/dsset



      print 'Probe Request: SSID=[%s], count=%d' % (ssid,count)
      try:
        # sendp() inijection function works at layer 2
        sendp(pkt,count=count,inter=0.1, verbose=0)
        print "Source %s Mac" % self.source
        print "Destination %s Mac" % dst
        print "BSSID %s " %  self.bssid
      except:
        raise


# main method
if __name__ == "__main__":
  #check for command line arhumnets
    if len(sys.argv) != 2:
        print "Usage %s monitor_interface" % sys.argv[0]
        print  "Usage %s Directed/broadcast nor implmented"
        sys.exit(1)

#grab an interface to pout into monitor mode
intf = str(sys.argv[1])
          
#Channnel hopping so porbe are sent on all avaiilable channnls. 
channel = 0
for i in range(10):
  import os, sys
  if channel < 13:
    channel = 1
    
  
  
  '''
  Use OS terminal commands to shutdown ther interface and switch channles
  also place in monitor mode
  '''  
  channel +=1
  iface = "wlan4"
  os.system("ifconfig %s down" % iface)
  os.system("sudo iw dev " + iface + " set type monitor")
  os.system("ifconfig "+iface+" up")
  os.system("iw dev %s set channel %d" % (iface, channel))
  
  
  #probe on each channel
  ptest = probeTesing(intf='wlan4', ssid="pine", dst="ff:ff:ff:ff:ff:ff")
  ptest.ProbeReq()

  

