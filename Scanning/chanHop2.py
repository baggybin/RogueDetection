import sys
from multiprocessing import Process
from scapy.all import *
import binascii
import os
from threading import Thread
from subprocess import Popen
import time


class scanning:
    """Class for a user of the chat client."""
    def __init__(self, intf):
        self.intf = intf
        self.count = 50
        self.counter = 10
        self.subcount = 10
        os.system("sudo ifconfig %s down" %  self.intf )
        os.system("sudo iw dev "+  self.intf + " set type monitor")
        os.system("sudo ifconfig %s up" %  self.intf )
        self.ssids = {}
        
    def ch_hop(self):
           for i in xrange(1,13,1):
            channel = i
           #channel = int(range(1,6,11))
           try:
               os.system("sudo iw dev %s set channel %d" % (self.intf, channel))
               print "channel Change", channel
           except Exception, err :
               print err             
    
        
    def sniffAP(self):
        print "Started Sniffing"
        def PacketHandler(frame):
            if frame.haslayer(Dot11) :
                if frame.type == 0 and frame.subtype == 8:
                    print "AP MAC: %s with SSID: %s " %(frame.addr2, frame .info)

        sniff(iface=self.intf, count = self.count, prn=PacketHandler)
              
        self.subcount +=1
        self.counter +=1
        if self.counter % 2 or (self.subcounter % 2) == 0:
            self.ch_hop()
        
        if self.counter == 20:
            sys.exit(0)
            
            


if __name__ == '__main__':
    s = scanning(intf="wlan4")
    s.sniffAP()
    
    

    

    
    
   
    

     
    

    
    
   
