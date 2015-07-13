import sys
from multiprocessing import Process
from scapy.all import *
import binascii
import os
os.system("ifconfig %s down" % "wlan2")
os.system("sudo iw dev wlan2 set type monitor")
os.system("ifconfig wlan2 up")
# print "Monitor setup done"

interface =""


def sniffAP(pkt):
    if pkt.haslayer(Dot11ProbeResp):
        ssid       = pkt[Dot11Elt].info
        print ssid


def ch_hopp():
    while True:
        try:
            channel = int(random.randrange(1,13))
            channel = 11
            #os.system("iwconfig %s channnel %d" % (interface, channel))
            try:
                proc = Popen(['iw', 'dev', interface, 'set', 'channel', channel], stdout=DN, stderr=PIPE)
            except OSError:
                sys.exit(1)
        except:
            pass
            
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage %s monitor_interface" % sys.argv[0]
        sys.exit(1)
    
    interface = sys.argv[1]
    sniff(iface=interface,prn=sniffAP)
