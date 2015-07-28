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
from tinydb import TinyDB, where
import logging
logger = logging.getLogger('tiny.py')
hdlr = logging.FileHandler("RougeID.log")
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
logger.setLevel(logging.WARNING)
from iw_karma_detect import *
from clock_skew_main1 import *
from subprocess import check_output
from decimal import * 



'''
Doesnt work as doersnty even recognose the evil twin
'''

class scanning:
    def __init__(self, db, interface):
        self.db = db
        self.interface = interface
        
    def scan(self):
        print "Scan Start"
        while True:
            cell = Cell.all(interface)
            print "Rescanning"
            timer = 0
            while timer < 100:
                timer +=1
                S = []
                count = 0
                for c in cell:
                    count += 1
                    #print ":"+ str(count), " ssid:", c.ssid
                        #create dictionary with informnation on the accesss point
                    SSIDS = {"no" : count ,"ssid": c.ssid, "channel":c.channel,"encrypted":c.encrypted, \
                                "frequency":c.frequency,"address":c.address, "signal":c.signal, "mode":c.mode}

                    #if not db.search((where('ssid') == ap["ssid"])) == []:
                   # res =  db.search(where('ssid') == c.ssid)
                    #print db.search(where('ssid') == c.ssid)
                    
                    print  "=----------------------------------"
                   # print  c.address
                    print "---------------------------------------"
                    if db.contains(where('ssid') == c.ssid):
                        print (db.contains((where('ssid') == c.ssid) & (where('address') == str(c.address))))
               
                    
                    
                    #if not res == []:
                    #    if db.search((where('ssid') == c.ssid) & (where('address') == c.address)) == []:
                    #        print "The BSSID adddress has Changed"
 
#{u'ssid': u'lyre', u'no': 1, u'encrypted': True, u'signal': -76, u'frequency': u'2.412 GHz', u'mode': u'Master', u'address': u'C0:4A:00:E4:B6:70', u'channel': 1}
                    #if str(res[0][1]) == c.address:
                    #    print "nothing has chnaged"
                    #else:
                    #    print "the BSSID Address has changed"
                   
                                        
                        #if db.search((where('ssid') == c.ssid) & (where('address') == c.address)) == []:
                        #    print 6 * 'A'
                        #else:
                        #    pass 
                    
        






def chann_change(channel):
    os.system("sudo ifconfig %s down" % "wlan4" )
    os.system("sudo iw dev "+ "wlan4" + " set type monitor")
    os.system("sudo ifconfig %s up" %  "wlan4")
    try:
        os.system("sudo iw dev %s set channel %d" % ("wlan4", channel))
        print "channel Change", channel
        print ""
    except Exception, err :
           print err
           
def managed():
    os.system("sudo ifconfig %s down" % "wlan4" )
    os.system("sudo iw dev "+ "wlan4" + " set type managed")
    os.system("sudo ifconfig %s up" %  "wlan4")


if __name__ == '__main__':
    from tinydb import TinyDB, where    
    interface = str(raw_input("Choose Interface for monitor: "))
    os.system("sudo ifconfig %s down" %  interface)
    os.system("sudo iwconfig "+  interface + " mode managed")
    os.system("sudo ifconfig %s up" %  interface )
    cell = Cell.all(interface)
    db = TinyDB('db.json')
    #db.purge()
    #Auth_AP = {}
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
    print "---------------------------------------------"
    
    loop = True
    while loop:
        try:
            input_var = int(input("1: Store Valid AP \n2: Disregard and Continue\n:"))     
            if input_var > 0 and input_var <= 2:
                loop = False
        except ValueError:
            pass
    
    if input_var == 1:
        if db.search((where('ssid') == ap["ssid"]) & (where('address') == str(ap["address"]))) == []:
            db.insert(ap)
        else:
            print "already Stored in the database"
        
        '''
        print all database
        '''
        print db.all()
        
    scan  = scanning("wlan4", db)
    scan.scan()
    