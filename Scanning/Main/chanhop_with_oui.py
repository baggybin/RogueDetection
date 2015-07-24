import sys
from multiprocessing import Process
from scapy.all import *
import binascii
import os
from threading import Thread
from subprocess import Popen
import time
from netaddr import *

'''
working very very slowly
'''

class scanning:
    """Class for a user of the chat client."""
    def __init__(self, intf, count):
        self.intf = intf
        self.counter = 0
        self.count = count
        self.accessPoints = []
        os.system("sudo ifconfig %s down" %  self.intf )
        os.system("sudo iw dev "+  self.intf + " set type monitor")
        os.system("sudo ifconfig %s up" %  self.intf )
        
    def ch_hop(self):
           channel = int(random.randrange(1,13))
           try:
               os.system("sudo iw dev %s set channel %d" % (self.intf, channel))
               print "channel Change", channel
           except Exception, err :
               print err             
 
        
    def sniffAP(self):
        print "Started Sniff"
        def PacketHandler(frame):
          try:
            FT = {0:"Management", 1:"Control", 2:"data"}
            FS = {0:"Association request", 1:"Association response", 2:"Reassociation request", 3:"Reassociation response", 4:"Probe request ", \
            5:"Probe response", 8:"Beacon"}
          except ValueError:
                print "unknown type"
     
          #print "tyupe", type(frame)
          if  frame.haslayer(Dot11):    
            if frame.type == 0 and frame.subtype == 8:
                if frame not in self.accessPoints:
                    print "AP MAC: %s "%(frame.addr2)    
                    self.accessPoints.append(frame)
                                
          self.counter +=1
          if self.counter % 2 == 0:
              self.ch_hop()
              

        sniff(iface=self.intf, count = self.count, prn=PacketHandler)
        
        return self.accessPoints
    
'''
Association request wlan.fc.type_subtype eq 0
Association response wlan.fc.type_subtype eq 1
Reassociation request wlan.fc.type_subtype eq 2
Reassociation response wlan.fc.type_subtype eq 3
Probe request wlan.fc.type_subtype eq 4
Probe response wlan.fc.type_subtype eq 5
Beacon wlan.fc.type_subtype eq 8
Announcement traffic indication map (ATIM) wlan.fc.type_subtype eq 9
Disassociate wlan.fc.type_subtype eq 10
Authentication wlan.fc.type_subtype eq 11
Deauthentication wlan.fc.type_subtype eq 12
Action frames wlan.fc.type_subtype eq 13
Block ACK Request wlan.fc.type_subtype eq 24
Block ACK wlan.fc.type_subtype eq 25
Power-Save Poll wlan.fc.type_subtype eq 26
Request to Send wlan.fc.type_subtype eq 27
Clear to Send wlan.fc.type_subtype eq 28 
'''


if __name__ == '__main__':
    s = scanning(intf="wlan4", count = 50)
    #s.sniffAP()
    f = s.sniffAP()
    
    print "-----------------------------------------------------------------------------------"
    #for frame in unuiqe:
    #  print frame.info, "  ", frame.addr2
    
    import manuf
    uniuqeSSID = []
    for frame in f:
        if frame.info not in uniuqeSSID:
            uniuqeSSID.append(frame.info)
            print frame.addr2
            p = manuf.MacParser()
            test = p.get_all(frame.addr2)
            if test.manuf is not None:
                print test
            else:
                print "Fake mac address"
  

  
  #net adddr was failing to validate mac OUI
            #mac = EUI(frame.addr2)
            #print  mac.is_iab()
            #iab = mac.iab
            #iab
            #if mac.is_iab():
            #   print  iab.registration()
            
        
        
    
    
    

    
    
   
    

     
    

    
    
   
def checkmylist(li):
    start=int(li[0])
    print start,"start"
    for e in li[1:]:
        a=int(e)
        if a==start+1:
            start=a
        else:
            return False
    return True