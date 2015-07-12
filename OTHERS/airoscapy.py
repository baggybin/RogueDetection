#!/usr/bin/env python
# airoscapy.py - Wireless AP scanner based on scapy
# version: 0.2
# Author: iphelix
import sys, os, signal
from multiprocessing import Process

from scapy.all import *

interface='' # monitor interface
aps = {} # dictionary to store unique APs

# process unique sniffed Beacons and ProbeResponses. 
def sniffAP(p):
    if (p.haslayer(Dot11ProbeResp)):
        ssid       = p[Dot11Elt].info
        bssid      = p[Dot11].addr3    
        channel    = int( ord(p[Dot11Elt:3].info))
        capability = p.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                {Dot11ProbeResp:%Dot11ProbeResp.cap%}")
        # Check for encrypted networks
        if re.search("privacy", capability): enc = 'Y'
        else: enc  = 'N'
        # Save discovered AP
        aps[p[Dot11].addr3] = enc
        # Display discovered AP    
        print "%02d  %s  %s %s" % (int(channel), enc, bssid, ssid) 

# Channel hopper
def channel_hopper():
    while True:
        try:
            channel = random.randrange(1,13)
            os.system("iw dev %s set channel %d" % (interface, channel))
        except KeyboardInterrupt:
            break
    

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage %s monitor_interface" % sys.argv[0]
        sys.exit(1)

    interface = sys.argv[1]

    print " KARMA ID" 
    print "CH ENC BSSID             SSID"

    # Start the channel hopper
    p = Process(target = channel_hopper)
    p.start()
    # Start the sniffer
    sniff(iface=interface,prn=sniffAP)



