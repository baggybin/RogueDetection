#!/usr/bin/env python
from collections import Counter
import traceback
import sys
from multiprocessing import Process, Value, Array, Manager

'''
Access Point:

stores marks for the accumulator scoring system
for individual access points
'''

class AccessPoint:
    def __init__(self, ID):
        self.ID = ID
        self.BSSID = None
        self.SSID = None
        self.sec = 0
        self.ch = 0
        self.KARMA = 0
        self.KARMA_BSSID = None
        self.AIRBASE = 0
        self.sqChange = 0
        self.timestampChange = 0
    
    def getID(self):
        return self.ID
    
    def setBSSID(self,B ):
        self.BSSID = B
    
    def setSSID(self, S):
        self.SSID = S
   
    def getBSSID(self):
        return self.BSSID 
    
    def getSSID(self):
        return self.SSID 
        
    def setSec(self):
        self.sec += 1
        
    def getSec(self):
        return self.sec
        
    def set_ch(self):
        self.ch += 1
        
    def get_ch(self ):
        return self.ch
        
    def setKARMA(self,k, address):
        self.KARMA += k
        self.KARMA_BSSID = address
    
    def setAirbaseNG(self):
        self.sqChange +=1
    
    def SettimestampChange(self):
        self.timestampChange +=1

    def getKARMA(self):
        return self.KARMA
    
    def getKARMABSSID(self ):
        return self.KARMA_BSSID

    def getAirbaseNG(self):
        return self.sqChange
    
    def gettimestampChange(self):
        return self.timestampChange        


import smtplib
import threading
from threading import Thread


'''
Starts accumulator scoring system,
which currently tests if there are KARMA or AIRbase-NG detections stored
in the shared memory space.

'''
class accumulator(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        # set as a daemon
        self.daemon = True
        self.Shared_Mem_Dictionary = None
        self.manager = None
        
    def run(self):
        print "Accumulator Starting\n"
        while True:
            try:
                # if there is an item in the shared memory dictionary 
                if bool(self.Shared_Mem_Dictionary) == True:
                    # make it into an iterable List
                    d=self.manager.list(self.Shared_Mem_Dictionary)
                    # iterate through the list and get the ID's (dictionary keys)
                    for i in d:
                        # test each AP for KARMA and email an alert
                        if self.Shared_Mem_Dictionary[i].getKARMA() > 0:
                            #IiGOmf81PYyenrwDrB86B3A
                            fromaddr = 'rougedetection@gmail.com'
                            toaddrs  = 'rougedetection@gmail.com'
                            SUBJECT  = "KARMA ACCESS POINT DETECTED!!"
                            text = 'KARMA ACCESS POINT Deteceted '  + str(self.Shared_Mem_Dictionary[i].getKARMABSSID())
                            msg = 'Subject: %s\n\n%s' % (SUBJECT, text)
                            username = "rougedetection"
                            password = "IiGOmf81PYyenrwDrB86B3A"
                            server = smtplib.SMTP('smtp.gmail.com:587')
                            server.starttls()
                            server.login(username,password)
                            server.sendmail(fromaddr, toaddrs, msg)
                            server.quit()
                            print "\nKARMA Alert Emailed!"
                            del(self.Shared_Mem_Dictionary[i])
                        # Test each AP for Airbase-NG detection and email an alert 
                        elif self.Shared_Mem_Dictionary[i].getAirbaseNG() > 0:
                            fromaddr = 'rougedetection@gmail.com'
                            toaddrs  = 'rougedetection@gmail.com'
                            SUBJECT  = "KARMA ACCESS POINT DETECTED!!"
                            text = 'AIRBASE-NG ACCESS POINT Deteceted '  + str(self.Shared_Mem_Dictionary[i].getSSID())
                            msg = 'Subject: %s\n\n%s' % (SUBJECT, text)
                            username = "rougedetection"
                            password = "IiGOmf81PYyenrwDrB86B3A"
                            server = smtplib.SMTP('smtp.gmail.com:587')
                            server.starttls()
                            server.login(username,password)
                            server.sendmail(fromaddr, toaddrs, msg)
                            server.quit()
                            print "\nAIRBASE-NG Alert Emailed!"                            
                            del(self.Shared_Mem_Dictionary[i])
                            
            except Exception, e:
                print "----", e
                print(traceback.format_exc())
                print(sys.exc_info()[0])
    '''
    add the shared memory dictionary and manager
    '''
    def setSMem(self,Shared_Mem_Dictionary, mgr):
        self.Shared_Mem_Dictionary = Shared_Mem_Dictionary
        self.manager = mgr

#    
#if __name__ == '__main__':    
#    a = accumulator()
#    AP = AccessPoint("KARMA")
#    AP.setKARMA(3,"aa:bb:cc:dd:ee:ff")
#    global manager
#    
#    Shared_Mem_Dictionary = manager.dict()
#    Shared_Mem_Dictionary[AP.getID()]=AP
#    a.setSMem(Shared_Mem_Dictionary)
#    a.start()
##    
#    

