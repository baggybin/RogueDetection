#!/usr/bin/env python
import sys, os, signal
from multiprocessing import Process
from scapy.all import *
import time
import subprocess
import re
'''
funtiom to randomlu hop through IEEE channels
may test it with sequential ordering
'''


class superHoppingtest:
    """Class for a user of the chat client."""
    def __init__(self):
        self.count = 0
        self.mac =""
        self.KARMAAP = []


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
            
            print "________________________________"
            print "Randomly Generated SSID ", fakeSSID
            print "setting to local interface"
            print "________________________________"
            
            
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
                    
            import subprocess
            #call a bash command to iwconfig to search for the generated SSID on that interfacE"
            output = subprocess.check_output("iwconfig wlan4 | grep 'ESSID:' | awk '{print $4}' | sed 's/ESSID://g' | sed 's/\"//g'",shell=True )
            from subprocess import Popen, PIPE
            #call iwconfig on interface and extract the assosiated MAC (BSSID), (which will onl7 exist is there is an assosoiation)
            
            output2 = subprocess.check_output("iwconfig wlan4 | grep 'Access Point:' | awk '{print $6}'", shell=True)
            
            
            if (output.strip()) == str(fakeSSID.strip()):
                if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", output2.lower()):
                    self.count +=1
                    print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
                    print "KARMA ACCESSS POINT DETECTED"
                    print "Fake SSID ", fakeSSID
                    print "Assososiatesd  SSID ", output
                    print "Assosoated Rouge BSSid", output2
                    if output2 in self.KARMAAP:
                        print  "KARMA BSSSID Seen Before"
                    self.KARMAAP.append(output2)
                    print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
            
            
            print "KARMA Dectected " + str(self.count) + " times"
            
            

if __name__ == '__main__':
    os.system("service network-manager stop")
    S = superHoppingtest()
    S.fakeSSID()
    
    print "Restarting Services"
    os.system("service network-manager start")
    os.system("dhclient")
    
    
    #import subprocess
    #p = subprocess.Popen(["python sniffer.py"], stdout=subprocess.PIPE)
    #out, err = p.communicate()





