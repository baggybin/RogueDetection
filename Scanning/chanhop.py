import sys
from multiprocessing import Process
from scapy.all import *
import binascii
import os
from threading import Thread
from subprocess import Popen
import time



'''
working very very slowly
'''

class scanning:
    """Class for a user of the chat client."""
    def __init__(self, intf):
        self.intf = intf
        self.counter = 0
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
        ap_set = set()
        print "Started Sniff"
        def PacketHandler(frame):
            # if pkt.haslayer(Dot11):#and (pkt.type, pkt.subtype) == (0, 0) and pkt.addr2 not in ap_set:
            #     #ap_set.add(pkt.addr2
            
          FT = {0:"Management", 1:"Control", 2:"data"}
          FS = {0:"Association request", 1:"Association response", 2:"Reassociation request", 3:"Reassociation response", 4:"Probe request ", \
          5:"Probe response", 8:"Beacon"}

          if  frame.haslayer(Dot11):    
            print FT[frame.type]
            print FS[frame.subtype]
                  
          self.counter +=1
          if self.counter % 5 == 0:
              self.ch_hop()  

        sniff(iface=self.intf, prn=PacketHandler)

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
    s = scanning(intf="wlan3")
    s.sniffAP()
    
    

    
    
   
    

     
    

    
    
   
