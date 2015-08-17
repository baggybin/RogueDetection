#!/usr/bin/env python
from collections import Counter


class AccessPoint:
    def __init__(self):    
        self.BSSID = None
        self.SSID = None
        self.sec = None
        self.ch = None
        self.KARMA = None
        self.KARMA_BSSID = None
        self.AIRBASE = None
        self.sqChange = None
        self.timestampChange = None
    
    def setBSSID(self,B ):
        self.BSSID = B
    
    def setSSID(self, S):
        self.SSID = S
   
    def getBSSID(self):
        return self.BSSID 
    
    def getSSID(self, S):
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
    
    def setAirbaseNG(self,sq ):
        self.sqChange +=1
    
    def SettimestampChange(self):
        self.timestampChange +=1

    def getKARMA(self):
        return self.KARMA_BSSID, self.KARMA
    
    def getAirbaseNG(self):
        return self.sqChange
    
    def gettimestampChange(self):
        return self.timestampChange        




class accumulator:
    def __init__(self, SSID, BSSID):
        self.SSID = ""
        self.BSSID = ""
        self.cnt = Counter()
        self.AP = None


#    
#if __name__ == '__main__':    
#    a = accumulator("name","aa:bb:cc:dd:ee:ff",1)
#    a.create_AP()
#    a.get_AP().set_ch(1)
#    
#    print a.get_AP().get_ch()
#    

