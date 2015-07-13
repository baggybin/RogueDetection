#!/usr/bin/env python
import sys, os, signal
from multiprocessing import Process
from scapy.all import *
import time
'''
funtiom to randomlu hop through IEEE channels
may test it with sequential ordering
'''


class superHoppingtest:
    """Class for a user of the chat client."""
    def __init__(self):
        self.count = 0


    def ch_hopp(self):
        while True:
            try:
                #CHoose Random Channnel 
                channel = int(random.randrange(1,13))
                #os.system("iwconfig %s channnel %d" % (interface, channel))
                try:
                    #execute processs on the terminal and sset channnel
                    proc = Popen(['iw', 'dev', interface, 'set', 'channel', channel], stdout=DN, stderr=PIPE)
                except OSError:
                    sys.exit(1)
            except:
                pass
     
        
    def fakeSSID(self):        
        for i in range(5):
            #gneerate a small 16 character SSID Randomly 
            fakeSSID =''.join(random.choice('0123456789ABCDEF') for i in range(16))
            print "fakeSSID", fakeSSID
            ''''
            Brinf the wireless interface down
            set its ESSID to randomly generated one
            then bring it back up
            The System will then automatically send out a probe request foor that network
            amd in this instamce( karma will rely and ususaly assosoiate)
            '''
            os.system("sudo ifconfig wlan4 down" )
            os.system("iwconfig wlan4 essid " + fakeSSID )
            os.system("ifconfig wlan4 up")
            time.sleep(20)
            
            
            '''
            Next Step try capture an assosiation from IWCONFIG with Fake SSid
            Thsi will Eliminate any to capture thge reponces
            '''
            
            #ROUGE = os.system("iwconfig wlan4 | grep 'ESSID:' | awk '{print $4}' | sed 's/ESSID://g' | sed 's/\"//g'")
            import subprocess
            #output = subprocess.check_output("iwconfig wlan4 | grep 'ESSID:' | awk '{print $4}' | sed 's/ESSID://g' | sed 's/\"//g'",shell=True )
            #print output
            #if i == 20:
            #    ch_hopp()
        
    
  
    
if __name__ == '__main__':
    S = superHoppingtest()
    S.fakeSSID()
    
    #import subprocess
    #p = subprocess.Popen(["python sniffer.py"], stdout=subprocess.PIPE)
    #out, err = p.communicate()





