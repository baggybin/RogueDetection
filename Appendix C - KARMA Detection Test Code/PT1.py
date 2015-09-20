# -*- coding: utf-8 -*-
#!/usr/bin/env python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import os
from scapy.all import *
import time
from multiprocessing import Process, Value, Array, Manager
from threading import Thread

from scapy.all import *

interface = "mon0"


observedclients = []


#!/usr/bin/env python
import sys, os, signal
from multiprocessing import Process
from scapy.all import *
import time





import threading

class ROUGEGEN(threading.Thread):
     def __init__(self):
         super(ROUGEGEN, self).__init__()
         self.interface="mon0"
         self.count=0
	 self.ROUGESSID = [] 
	 
     def sniffmgmt(p):
	if p.haslayer(Dot11):
	    if p.type == 0 and p.subtype == 5:
		print p.addr2, p.subtype,  p.info
		self.ROUGESSID.append(p)
		print "here"
		
	
     sniff(iface="mon0", prn=sniffmgmt, count = 10)


		

thread1 = ROUGEGEN()
thread1.start()

























#def sniffmgmt(p):
## Define our tuple (an immutable list) of the 3 management frame
## subtypes sent exclusively by clients. I got this list from Wireshark.
##tamgmtstypes = (0, 2, 4, 5)
## Make sure the packet has the Scapy Dot11 layer present
#
#    #print "we are heere"
#    ROUGESSID=[]
#    if p.haslayer(Dot11):
#    # Check to make sure this is a management frame (type=0) and that
#    # the subtype is one of our management frame subtypes indicating a
#    # a wireless client
#	if p.type == 0 and p.subtype == 5:
#	# We only want to print the MAC address of the client if it
#	# hasn't already been observed. Check our list and if the
#	# client address isn't present, print the address and then add
#	# it to our list
#	    print p.addr2, p.subtype,  p.info
#	    ROUGESSID.append(p)
#
## With the sniffmgmt() function complete, we can invoke the Scapy sniff()
## function, pointing to the monitor mode interface, and telling Scapy to call
## the sniffmgmt() function for each packet received. Easy!
#    sniff(iface=interface, prn=sniffmgmt, count = 100)



#'''
#funtiom to randomlu hop through IEEE channels
#may test it with sequential ordering
#'''
#def ch_hopp():
#    while True:
#        try:
#            #CHoose Random Channnel 
#            channel = int(random.randrange(1,13))
#            #os.system("iwconfig %s channnel %d" % (interface, channel))
#            try:
#                #execute processs on the terminal and sset channnel
#                proc = Popen(['iw', 'dev', interface, 'set', 'channel', channel], stdout=DN, stderr=PIPE)
#            except OSError:
#                sys.exit(1)
#        except:
#            pass           
#for i in range(5):
#    #gneerate a small 16 character SSID Randomly 
#    fakeSSID =''.join(random.choice('0123456789ABCDEF') for i in range(16))
#    print fakeSSID
#    ''''
#    Brinf the wireless interface down
#    set its ESSID to randomly generated one
#    then bring it back up
#    The System will then automatically send out a probe request foor that network
#    amd in this instamce( karma will rely and ususaly assosoiate)
#    '''
#    os.system("sudo ifconfig wlan4 down" )
#    os.system("iwconfig wlan4 essid " + fakeSSID )
#    os.system("ifconfig wlan4 up")
#    time.sleep(10)
#    
#    
#    '''
#    Next Step try capture an assosiation from IWCONFIG with Fake SSid
#    Thsi will Eliminate any to capture thge reponces
#    '''
#    #ROUGE = os.system("iwconfig wlan4 | grep 'ESSID:' | awk '{print $4}' | sed 's/ESSID://g' | sed 's/\"//g'")
#    import subprocess
    #output = subprocess.check_output("iwconfig wlan4 | grep 'ESSID:' | awk '{print $4}' | sed 's/ESSID://g' | sed 's/\"//g'",shell=True )
    #print output
    #if i == 20:
    #    ch_hopp()



# def sniffmgmt(p):
#     # Define our tuple (an immutable list) of the 3 management frame
#     # subtypes sent exclusively by clients. I got this list from Wireshark.
#     stamgmtstypes = (0, 2, 4, 5)
#     # Make sure the packet has the Scapy Dot11 layer present
#     if p.haslayer(Dot11):
#         # Check to make sure this is a management frame (type=0) and that
#         # the subtype is one of our management frame subtypes indicating a
#         # a wireless client
#         if p.type == 0 and p.subtype == 5:
#             # We only want to print the MAC address of the client if it
#             # hasn't already been observed. Check our list and if the
#             # client address isn't present, print the address and then add
#             # it to our list
# 	    print p.addr2, p.subtype,  p.info
	    
# # With the sniffmgmt() function complete, we can invoke the Scapy sniff()
# # function, pointing to the monitor mode interface, and telling Scapy to call
# # the sniffmgmt() function for each packet received. Easy!
# sniff(iface=interface, prn=sniffmgmt)
















