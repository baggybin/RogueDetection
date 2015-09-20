import sys
from multiprocessing import Process
from scapy.all import *
import binascii
import os



class scanning:
    """Class for a user of the chat client."""
    def __init__(self, intf):
        self.intf = intf
        print self.intf 
        

    def mon():
        os.system("sudo ifconfig %s down" % self.intf)
        os.system("sudo iw dev "+ self.intf + " set type monitor")
        os.system("sudo ifconfig %s up" % self.intf)
    
    def sniff():
        sniff(iface=self.intf,prn=sniffAP)
    
    def sniffAP(pkt):
        if pkt.haslayer(Dot11ProbeResp):
            ssid  = pkt[Dot11Elt].info
            print ssid
    
    
    def ch_hopp():
        while True:
            try:
                channel = int(random.randrange(1,13))
                try:
                     proc = Popen(['iw', 'dev', interface, 'set', 'channel', channel], stdout=DN, stderr=PIPE)
                except OSError:
                     sys.exit(1)
                     print "Error in channel Change"
            except IOError:
                pass
            

if __name__ == '__main__':
   # proc = subprocess.Popen("python sniffer.py",shell=True)
    S = scanning(self, intf="wlan3")
    s.mon()
    
    

    
    
   
