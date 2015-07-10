## -*- coding: utf-8 -*-
#from scapy.all import *
#import json
#def proc(p):
#        if ( p.haslayer(Dot11ProbeReq) ):
#                mac=re.sub(':','',p.addr2)
#                ssid=p[Dot11Elt].info
#                ssid=ssid.decode('utf-8','ignore')
#                if ssid == "":
#                        ssid="<BROADCAST>"
#                print "%s:%s" %(mac,ssid)
#		
#		if ssid == "pine":
#		  print ""
#		  print p.summary
#		
#
#
#sniff(iface="mon0",prn=proc)


R = RadioTap()
R.version=0
R.pad32=34
R.present="TSFT+Flags+Rate+Channel+dBm_AntSignal+Antenna+b14"
R.notdecoded='\xb1\xdbq\xbd\x00\x00\x00\x00\x10\x02q\t\xa0\x00\xc7\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'



