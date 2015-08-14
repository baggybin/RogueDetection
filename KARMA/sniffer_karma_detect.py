#!/usr/bin/env python
#imporetd
import sys, os, signal
from multiprocessing import Process
from scapy.all import *
import time
import subprocess
import re
import os
import time
from threading import Thread
from superHoppingtest import *
import threading
import time
import logging


'''
KARAMID Class TO gneerate randon SSID's and apply them to a local interface
so that the the local kernel will probe for them 
'''
class karmaid:
    """main class"""
    def __init__(self):
        self.count = 0
        self.mac =""
        self.KARMAAP = []
      
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
            output = subprocess.check_output("sudo iwconfig wlan4 | grep 'ESSID:' | awk '{print $4}' | sed 's/ESSID://g' | sed 's/\"//g'",shell=True )
            from subprocess import Popen, PIPE
            #call iwconfig on interface and extract the assosiated MAC (BSSID), (which will onl7 exist is there is an assosoiation)
            output2 = subprocess.check_output("sudo iwconfig wlan4 | grep 'Access Point:' | awk '{print $6}'", shell=True)
            
            
            
            """
            If the Generated essis matched the Iwconfig mac for the particiluar iterface
            and has an Assossiation to an acccess point, it connecteced to the
            fake AP
            """
            ##take and strip left and right whote space
            if (output.strip()) == str(fakeSSID.strip()):
                #  regular expression match for a MAC format adddress of the assosoiated mac
                if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", output2.lower()):
                    #add a match
                    self.count +=1
                    print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
                    print "KARMA ACCESSS POINT DETECTED"
                    print "Fake SSID ", fakeSSID
                    print "Assososiatesd  SSID ", output
                    print "Assosoated Rouge BSSid", output2
                    if output2 in self.KARMAAP:
                        print  "KARMA BSSSID Seen Before"
                    #store BAD access point
                    self.KARMAAP.append(output2)
                    print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
            print "KARMA Dectected " + str(self.count) + " times"
            return self.count
 
        


class sniffer():
    def __init__(self):
        self.sniffed = []
            
    def run(self):
        interface = "mon0"
        print "Obzservation Thread"
        # Next, declare a Python list to keep track of client MAC addresses
        # that we have already seen so we only print the address once per client.
        observedclients = []
        
        # The sniffmgmt() function is called each time Scapy receives a packet
        # (we'll tell Scapy to use this function below with the sniff() function).
        # The packet that was sniffed is passed as the function argument, "p".
        def sniffmgmt(p):
            # Make sure the packet has the Scapy Dot11 layer present
            if p.haslayer(Dot11):
                # Check to make sure this is a management frame (type=0) and that
                # the subtype is one of our management frame subtypes indicating a
                # a wireless client
                if p.type == 0 and p.subtype == 5:
                    # We only want to print the MAC address of the client if it
                    # hasn't already been observed. Check our list and if the
                    # client address isn't present, print the address and then add
                    # it to our list
                    print p.addr2, p.subtype, p.info          
        # With the sniffmgmt() function complete, we can invoke the Scapy sniff()
        # function, pointing to the monitor mode interface, and telling Scapy to call
        # the sniffmgmt() function for each packet received. Easy!
        sniff(iface=interface, prn=sniffmgmt)
                 
            

if __name__ == '__main__':
    os.system("service network-manager stop")
    
    s = sniffer()
    k = karmaid()   
    
    
    import threading, time
    #p = Process(target=s.run())
    #
    #p2 = Process(target=k.fakeSSID())

    #thread = threading.Thread(target=s.run())
    #thread2 = threading.Thread(target=k.fakeSSID())
    #thread.start()
    #thread2.start()
    
    from shelljob import job
    jm = job.FileMonitor()
    jm.run([
    [ s.run() ],
    k.fakeSSID(),
    ])
    #subprocess.Popen(['k.fakeSSID()'])
    #subproce(ss.Popen(['s.run()'])
    #
    #
    #S = superHoppingtest()
    #try:
    #    thread.start_new_thread( k.fakeSSID(), ("Thread-2", 4, ) )
    #    thread.start_new_thread( s.run(), ("Thread-1", 2, ) )
    #except Exception, err:
    #    print Exception, err
        
    print "Restarting Services"
    os.system("service network-manager start")
    os.system("dhclient")
    
    
    #import subprocess
    #p = subprocess.Popen(["python sniffer.py"], stdout=subprocess.PIPE)
    #out, err = p.communicate()





