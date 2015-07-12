#!/usr/bin/env python
import sys, os, signal
from multiprocessing import Process
from scapy.all import *
import time


def ch_hopp():
    while True:
        try:
            
            channel = int(random.randrange(1,13))
            #os.system("iwconfig %s channnel %d" % (interface, channel))
            try:
                proc = Popen(['iw', 'dev', interface, 'set', 'channel', channel], stdout=DN, stderr=PIPE)
            except OSError:
                sys.exit(1)
        except:
            pass
 
    
           
for i in range(5):
    fakeSSID =''.join(random.choice('0123456789ABCDEF') for i in range(16))
    print fakeSSID
    os.system("sudo ifconfig wlan4 down" )
    os.system("iwconfig wlan4 essid " + fakeSSID )
    os.system("ifconfig wlan4 up")
    time.sleep(20)
    #ROUGE = os.system("iwconfig wlan4 | grep 'ESSID:' | awk '{print $4}' | sed 's/ESSID://g' | sed 's/\"//g'")
    import subprocess
    output = subprocess.check_output("iwconfig wlan4 | grep 'ESSID:' | awk '{print $4}' | sed 's/ESSID://g' | sed 's/\"//g'",shell=True )
    print output
    if i == 20:
        ch_hopp()