import sys
from multiprocessing import Process
from scapy.all import *
import binascii
import os
from threading import Thread
from subprocess import Popen
import time

'''
Class for scanninf beacons from access points
in proxitmity and then creating a list.
the code channnel hops.....
has issues with some SSID values being corrupted, possiblke due to the
channel hoppping. But sometimes there is no corruption so could be the driver of
wifi device im using.
'''

class scanning:
    """Class for scanning for access points"""
    # constructor with interface and packet count iniilizsers 
    def __init__(self, intf, count):
        #monitor interface
        self.intf = intf
        #counter for hopping
        self.counter = 0
        # no of packets to sniff on the medium
        self.count = count
        #store access points in a list
        self.accessPoints = []
        '''
        system call to put the interfac into monitor mode via terminal commands
        '''
        os.system("sudo ifconfig %s down" %  self.intf )
        os.system("sudo iw dev "+  self.intf + " set type monitor")
        os.system("sudo ifconfig %s up" %  self.intf )
        
        
    '''
    Method to randomly hop though IEEE channels
    could be more optimiased to only hop over channels
    that over lap
    '''
    def ch_hop(self):
           channel = int(random.randrange(1,13))
           try:
               os.system("sudo iw dev %s set channel %d" % (self.intf, channel))
               print "channel Change", channel
           except Exception, err :
               print err             
 
        
    '''
    Handles sniffing the packets from the monitor interface
    and passing then to a packet handler
    '''
    def sniffAP(self):
        print "Started Sniff"
        #packet handler for the sniffer
        #any captured packets are sent here for processsing
        def PacketHandler(frame):
          #small function for later use to see
          #types of packets
          try:
            FT = {0:"Management", 1:"Control", 2:"data"}
            FS = {0:"Association request", 1:"Association response", 2:"Reassociation request", 3:"Reassociation response", 4:"Probe request ", \
            5:"Probe response", 8:"Beacon"}
          except ValueError:
                print "unknown type"
     
          # checks if IEEE 802.11 Frame BEACON or PROBE REQUEST
          if  frame.haslayer(Dot11):    
            if frame.type == 0 and frame.subtype == 8 or frame.type == 0 and frame.subtype == 5:
                #if not stored allready store 
                if frame not in self.accessPoints:
                    print "Acccesss MAC: %s with SSID: %s " %(frame.addr2, frame.info)    
                    self.accessPoints.append(frame)
                  
          '''
          Defunt sorting mechanism
          '''
          #def unique(lst):
          #  return [] if lst==[] else [lst[0]] + unique(filter(lambda x: x!= lst[0], lst[1:]))  
          #
          #u = unique(self.accessPoints)
          #for frame in u:
          #  print frame.info
          #from operator import itemgetter
          #sorted(self.accessPoints, key=itemgetter('ssid', 'info'))

          '''
          Counter to call a channnel hop ever 2 frames
          could be adjusted
          '''
          self.counter +=1
          if self.counter % 2 == 0:
              self.ch_hop()
              time.sleep(.5)

        #main Scapy sniff metrhod, with monitor interface, packet countwer and handler
        #argumeents
        sniff(iface=self.intf, count = self.count, prn=PacketHandler)
        
        return self.accessPoints
    
        '''
        -----WireShark Fileters ---- same apply
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

'''
progam will start here
MAIN if called as a script
'''
if __name__ == '__main__':
    s = scanning(intf="wlan4", count = 50)
    #s.sniffAP()
    f = s.sniffAP()
    
    print "-----------------------------------------------------------------------------------"
    #for frame in unuiqe:
    #  print frame.info, "  ", frame.addr2
    
    ##store and prints out unuique SSID
    uniuqeSSID = []
    for frame in f:
        if frame.info not in uniuqeSSID:
            uniuqeSSID.append(frame.info)
            print frame.addr2 , " : " ,frame.info
            val = frame.addr2 , " : " ,frame.info
            f = open('written_file.txt','a')
            f.write(str(val)+"\n")
            
            
            
    
    
    

    
    
   
    

     
    

    
    
   
