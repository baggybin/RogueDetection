import sys
from multiprocessing import Process
from scapy.all import *
import binascii
import os
from threading import Thread
from subprocess import Popen
import time
from netaddr import *
import manuf
import math

'''
working very very slowly

same BSSID but different other attributes such as encyption, channnel

same AP ESSID with different BSSID

OUI

'''
class MyError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class scanning:
    """Class for a user of the chat client."""
    def __init__(self, intf, count, channel,BSSID, SSID ):
        self.intf = intf
        self.BSSID = BSSID
        self.SSID = SSID
        
        self.seq1 = 0
        self.seq2 = 0
        self.diff = 0
        self.seq4 = 0
        self.test = 1
        
        self.seq_list = []
        self.mean = 0
        self.counter = 0
        self.channel = channel
        self.count = count
        self.accessPointsSQ = []
         
        os.system("sudo ifconfig %s down" %  self.intf )
        os.system("sudo iw dev "+  self.intf + " set type monitor")
        os.system("sudo ifconfig %s up" %  self.intf )
        try:
            os.system("sudo iw dev %s set channel %d" % (self.intf, self.channel))
            print "channel Change", channel
        except Exception, err :
               print err


    def checkTheSeq(self, li):
        start=int(li[0])
        print start,"start"
        for e in li[1:]:
            a=int(e)
            if a > start:
                start=a
            else:
                return False
        return True

          
    def sniffAP(self):
        print "------------------Started-----------------------------------------------"
        def PacketHandler(frame):
          if not self.BSSID == frame.addr2:
            print "Same SSID with Different BSSID address"
            p = manuf.MacParser()
            test = p.get_all(frame.addr2)
            if test.manuf is not None:
                print "real OUI Code"
                
          if  frame.haslayer(Dot11) and frame.type == 0 and frame.subtype == 8:
            try:
                if frame.info == self.SSID or self.BSSID == frame.addr2:
                    try:
                        
                        print frame.SC
                        self.seq1 = frame.SC
                        self.seq_list.append(frame.SC)
                        self.counter += 1
                        
                        if self.counter == 10:                          
                            val = self.checkmylist(self.seq_list)
                            self.seq_list = []
                            print "--------------- ", val
                            self.counter = 0
                        
                        ##sig_str = -(256-ord(frame.notdecoded[1]))
                        ##resets when the seqeunece numbers restart at 0 from (65536)
                        ##stops anomolooous detection of Evil Twin
                        #print frame.SC
                        #frame_seq = frame.SC * frame.SC
                        #if frame_seq == 0:
                        #    self.seq2 = 0
                        #    self.seq1 = 0
                        #
                        #    #, " RSSI ", self.parsePacket(frame)#sig_str
                        #if  self.test == 1:
                        #    self.seq1 = frame_seq
                        #
                        #    
                        #if  self.test == 2:
                        #    self.seq2 = frame_seq
                        #    self.test = 1 
                        #    print "Difference ", ((self.seq2 - self.seq1))
                        #    self.diff = ((self.seq2 - self.seq1))
                        #
                        #self.test = 2
                        #
                        # 
                        #if  self.diff > (self.seq2- self.seq1) and self.test == 2:
                        #    print "possible ROUGE AP With Alternbate Sequence Numbers"
                        #    sys.exit()
                        
                        
                        self.accessPointsSQ.append(frame.SC)
                    except  Exception,e:
                        print "error", e
            except:
                pass

                      
        sniff(iface=self.intf, count = self.count, prn=PacketHandler)
        return self.accessPointsSQ
    
        



# lyre
# "C0:4A:00:E4:B6:70"

if __name__ == '__main__':
    s = scanning(intf="wlan4", count = 6000, channel = 10, BSSID= "00:50:18:66:89:D6", SSID="Zoom")
    #s.sniffAP()
    f = s.sniffAP()
    
    #print "-----------------------------------------------------------------------------------"
    #mean = 0
    #counter = 0
    #for sc in f:
    #    counter +=1
    #    mean = mean + sc   
    #print mean/counter
        
    
