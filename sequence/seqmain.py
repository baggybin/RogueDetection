import sys
from multiprocessing import Process
from scapy.all import *
import binascii
import os
from threading import Thread
from subprocess import Popen
import time
from netaddr import *
import manuf
import math
import threading
from wifi import Cell, Scheme

'''
working very very slowly

same BSSID but different other attributes such as encyption, channnel

same AP ESSID with different BSSID

OUI

'''
class scanning:
    """Class for a user of the chat client."""
    def __init__(self, intf, count, channel,BSSID, SSID, WIFIDATA,user_choice):
        self.intf = intf
        self.BSSID = BSSID
        self.SSID = SSID
        self.WIFIDATA = WIFIDATA
        self.user_choice = user_choice
        
        self.seq1 = 0
        self.flag1 = 0
        
        self.counter = 0
        self.channel = channel
        self.count = count
        self.accessPointsSQ = []
        self.seq_list = []
        
        
        

        #self.ThreadingExample = None
         
        os.system("sudo ifconfig %s down" %  self.intf )
        os.system("sudo iw dev "+  self.intf + " set type monitor")
        os.system("sudo ifconfig %s up" %  self.intf )
        try:
            os.system("sudo iw dev %s set channel %d" % (self.intf, self.channel))
            print "channel Change", channel
        except Exception, err :
               print err 


    def checkTheSeq(self, li):
        start=int(li[0])
        print start,"Sequence"
        for e in li[1:]:
            a=int(e)
            if a > start:
                start=a
            else:
                return False
        return True
    
    
    def oui(self, frame):
        result = False
        p = manuf.MacParser()
        test = p.get_all(frame.lower())
        if test.manuf is not None:
            print "Real OUI Code"
            result = True
        return result
    
       
    def sniffAP(self):
        print "------------------Started-----------------------------------------------"
        def PacketHandler(frame):      
          if  frame.haslayer(Dot11) and frame.type == 0 and frame.subtype == 8:
            if self.flag1 == 0:
                result = self.oui(frame.addr2)
                print "********************    OUI ", result
                self.flag1 = 1

        
                ## direcly from Airoscapy
                capability = frame.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                {Dot11ProbeResp:%Dot11ProbeResp.cap%}")
                if re.search("privacy", capability): enc = True
                else: enc  = False
                
                
            
                
                if not self.WIFIDATA["encrypted"] == enc:
                    print "Encyption Has been chnaged"
                
                time.sleep(2)
              
            try:
                if frame.info == self.SSID or self.BSSID.lower() == frame.addr2:
                    try:
                        print frame.SC
                        self.seq1 = frame.SC
                        self.seq_list.append(frame.SC)
                        self.counter += 1
                        
                        if self.counter == 50:                          
                            val = self.checkTheSeq(self.seq_list)
                            print "----------------------------------------------------------------------- ", val
                            if val == False:
                                print "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< Possible Evil Twin >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> "
                            self.seq_list = []
                            self.counter = 0
                            result = self.oui(frame.addr2)
                            print "******************** OUI ", result
                            if result == False:
                                print "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< Possible Mac Spoof >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> "
                        self.accessPointsSQ.append(frame.SC)
                    except  Exception,e:
                        print "error", e
            except:
                pass

                      
        sniff(iface=self.intf, count = self.count, prn=PacketHandler)
        return self.accessPointsSQ
    
        
#
#class ThreadingExample(object):
#    """ Threading example class
#    The run() method will be started and it will run in the background
#    until the application exits.
#    """
#    def __init__(self, interval=1, mac = ""):
#        """ Constructor
#        :type interval: int
#        :param interval: Check interval, in seconds
#        """
#        self.interval = interval
#        self.frame = mac
#        thread = threading.Thread(target=self.run, args=())
#        thread.daemon = True                            # Daemonize thread
#        thread.start()                             # Start the execution=
#        
#    def run(self):
#        result = False
#        p = manuf.MacParser()
#        test = p.get_all(self.frame.lower())
#        if test.manuf is not None:
#            print "Real OUI Code"
#            result = True
#        return result
#        


# lyre
# "C0:4A:00:E4:B6:70"
# zoom1
# "00:50:18:66:89:D6"


if __name__ == '__main__':
    interface = str(raw_input("Choose iface: "))
    os.system("sudo ifconfig %s down" %  interface)
    os.system("sudo iwconfig "+  interface + " mode managed")
    os.system("sudo ifconfig %s up" %  interface )
    cell = Cell.all(interface)
    
    Auth_AP = {}
    S = []
    #have a counter for user choice input
    count = 0

    for c in cell:
        count += 1
        print ":"+ str(count), " ssid:", c.ssid
            #create dictionary with informnation on the accesss point
        SSIDS = {"no" : count ,"ssid": c.ssid, "channel":c.channel,"encrypted":c.encrypted, \
                    "frequency":c.frequency,"address":c.address, "signal":c.signal, "mode":c.mode}
            #append this dictionary to a list
        S.append(SSIDS)
    
    ## get choice from the user
    input_var = int(input("Choose: "))
    print "-----------------------------------------"

    ap = S[input_var - 1]
    print ap["ssid"]
    print ap["address"]
    print ap["encrypted"]
    print ap["channel"]
    # store aurtorised in a dictionary
   #Auth_AP[ap["ssid"]] = ap
   #print "__________________"
   #print Auth_AP 
   
   
   
  
    #s = scanning(intf="wlan4", count = 6000, channel=ap["channel"], BSSID=ap["address"], SSID=ap["ssid"], WIFIDATA=SSIDS, user_choice=input_var)
    #f = s.sniffAP()

    
