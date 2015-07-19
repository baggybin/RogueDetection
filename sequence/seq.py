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
        self.seq3 = 0
        self.seq4 = 0
        self.counter = 0
        self.channel = channel
        self.count = count
        self.accessPoints = []
        self.radiotap_formats = {"TSFT":"Q", "Flags":"B", "Rate":"B",
        "Channel":"HH", "FHSS":"BB", "dBm_AntSignal":"b", "dBm_AntNoise":"b",
        "Lock_Quality":"H", "TX_Attenuation":"H", "dB_TX_Attenuation":"H",
        "dBm_TX_Power":"b", "Antenna":"B",  "dB_AntSignal":"B",
        "dB_AntNoise":"B", "b14":"H", "b15":"B", "b16":"B", "b17":"B", "b18":"B",
        "b19":"BBB", "b20":"LHBB", "b21":"HBBBBBH", "b22":"B", "b23":"B",
        "b24":"B", "b25":"B", "b26":"B", "b27":"B", "b28":"B", "b29":"B",
        "b30":"B", "Ext":"B"}
        
        
        os.system("sudo ifconfig %s down" %  self.intf )
        os.system("sudo iw dev "+  self.intf + " set type monitor")
        os.system("sudo ifconfig %s up" %  self.intf )
        try:
            os.system("sudo iw dev %s set channel %d" % (self.intf, self.channel))
            print "channel Change", channel
        except Exception, err :
               print err
 
 
 
    '''
    method extraced from https://github.com/azz2k/scapy-rssi/blob/master/scapy-rssi.py
    scapy-rssi
    unfortunauarty same numbers
    '''
    def parsePacket(self, pkt):
        if pkt.haslayer(Dot11):
            if pkt.addr2 is not None:
                field, val = pkt.getfield_and_val("present")
                names = [field.names[i][0] for i in range(len(field.names)) if (1 << i) & val != 0]
                if "dBm_AntSignal" in names:
          # decode radiotap header
                    fmt = "<"
                    rssipos = 0
                for name in names:
            # some fields consist of more than one value
                    if name == "dBm_AntSignal":
              # correct for little endian format sign
                        rssipos = len(fmt)-1
                        fmt = fmt + self.radiotap_formats[name]
          # unfortunately not all platforms work equally well and on my arm
          # platform notdecoded was padded with a ton of zeros without
          # indicating more fields in pkt.len and/or padding in pkt.pad
                    decoded = struct.unpack(fmt, pkt.notdecoded[:struct.calcsize(fmt)])
            return pkt.addr2, decoded[rssipos]       
        return None,None
       


        
    def sniffAP(self):
        print "Started Sniff"
        def PacketHandler(frame):
          if  frame.haslayer(Dot11):
            try:
                if frame.info == "lyre":
                    try:
                        #sig_str = -(256-ord(frame.notdecoded[1]))
                        print frame.SC #, " RSSI ", self.parsePacket(frame)#sig_str
                        #print -(256-ord(frame.notdecoded[1]))
                    except:
                        print "error"
            except:
                print "frame doesnt have SSID"
            #if frame.type == 0 and frame.subtype == 8:
            #    if frame not in self.accessPoints:
            #        print "AP MAC: %s with SSID: %s " %(frame.addr2, frame.info)
            #        try:
            #            print "seq" , frame.SC
            #        except exception:
            #            print "ex"
            #        self.accessPoints.append(frame)
                    
            
        sniff(iface=self.intf, count = self.count, prn=PacketHandler)
        return self.accessPoints
    






if __name__ == '__main__':
    s = scanning(intf="wlan4", count = 300, channel = 1, BSSID= "C0:4A:00:E4:B6:70", SSID="lyre")
    #s.sniffAP()
    f = s.sniffAP()
    
    print "-----------------------------------------------------------------------------------"
