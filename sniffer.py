# -*- coding: utf-8 -*-
#!/usr/bin/env python

import os
from scapy.all import *
# import json

#os.system("sudo service network-manager stop")
os.system("sudo ifconfig wlan2 down" )
os.system("sudo iwconfig wlan2 mode monitor" )
os.system("sudo ifconfig wlan2 up")

# def proc(p):
#        if (p.haslayer(Dot11ProbeResp)):
# 	  print "founsd"
# 	  print p[Dot11Elt].ID


# sniff(iface="wlan3",prn=proc
from scapy.all import *
ap_set = set()

def PacketHandler(pkt):
	if  pkt.haslayer(Dot11ProbeResp):
	    print pkt[Dot11].info

      
sniff(iface="wlan2", prn=PacketHandler)