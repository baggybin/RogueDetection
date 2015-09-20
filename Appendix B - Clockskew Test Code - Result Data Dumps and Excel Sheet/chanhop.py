import sys, os 
from multiprocessing import Process
from scapy.all import *
import binascii

os.system("ifconfig %s down" % "wlan0")
os.system("sudo iw dev wlan0 set type monitor")
os.system("ifconfig wlan0 up")
# print "Monitor setup done"

interface =""

def sniffAP(p):
    if ((p.haslayer(Dot11Beacon))):
        ssid       = p[Dot11Elt].info
        bssid      = p[Dot11].addr3    
        channel    = int(ord(p[Dot11Elt:3].info))
        print "%d  %s  %s" % (channel, bssid, ssid) 
        print p.sprintf("%Dot11.addr2%[%Dot11Elt.info%|%Dot11Beacon.cap%]")
        print "RSSI"
        print -(256 - int(binascii.hexlify(p.notdecoded[-4:-3]), 16))
        print "Sequence Number"
        print p.SC

def ch_hopp():
    while True:
        try:
            channel = random.randrange(1,13)
            os.system("iw dev %s set channel %d" % (interface, channel))
            time.sleep(1)
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage %s monitor_interface" % sys.argv[0]
        sys.exit(1)
        
        
    

    interface = sys.argv[1]
    
    
    os.system("sudo ifconfig " + interface + " down" )
    os.system("iwconfig " + interface + " essid " + fakeSSID )
    os.system("ifconfig " + interface + " up")
    
    
    
    
    print "CH  BSSID             SSID"
    p = Process(target = ch_hopp)
    p.start()

    sniff(iface=interface,prn=sniffAP)
