#!/usr/bin/env python
#imports
import sys, os
from scapy.all import *
import subprocess
import re
'''
KARAMID Class TO generate random SSID's and apply them to a local interface
so that the the local kernel will probe for them 
'''
class karmaid:
    """main class constructor"""
    def __init__(self):
        #count the the karma Rouge
        self.count = 0
        #Store them
        self.KARMAAP = []
        #How many time tto run the test
        self.range = 3
        os.system("service network-manager stop")
        
    def fakeSSID(self):
        for i in range(self.range):   
            #generate a small 16 character sequence SSID Randomly 
            fakeSSID =''.join(random.choice('0123456789ABCDEF') for i in range(16))
            
            print "________________________________"
            print "Randomly Generated SSID ", fakeSSID
            print "setting to local interface"
            print "Initiating probe Request for ", fakeSSID
            print "________________________________"
            
            
            ''''
            Bring the wireless interface down
            set its ESSID to randomly generated one
            then bring it back up
            The System will then automatically send out a probe request for that network
            and in this instance( karma will rely and usually associate)
            '''
            os.system("sudo ifconfig wlan4 down" )
            time.sleep(1)
            os.system("iwconfig wlan4 essid " + fakeSSID )
            os.system("ifconfig wlan4 up")
            # requires at least 20 seconds to associate
            time.sleep(25)
            
            if self.range == 2 and self.count == 0:
                time.sleep(10)
            '''
            Next Step try capture an association from IWCONFIG with Fake SSid
            This will Eliminate any to capture the rep onces
            '''
                    
            import subprocess
            #call a bash command to iwconfig to search for the generated SSID on that interfacE"
            output = subprocess.check_output("sudo iwconfig wlan4 | grep 'ESSID:' | awk '{print $4}' | sed 's/ESSID://g' | sed 's/\"//g'",shell=True )
            from subprocess import Popen, PIPE
            #call iwconfig on interface and extract the associated MAC (BSSID), (which will onl7 exist is there is an association)
            output2 = subprocess.check_output("sudo iwconfig wlan4 | grep 'Access Point:' | awk '{print $6}'", shell=True)
            
            
            
            """
            If the Generated ESSID matched the iwconfig mac for the participial interface
            and has an Association to an access point, it connected to the
            fake AP
            """
            ##take and strip left and right white space
            if (output.strip()) == str(fakeSSID.strip()):
                #  regular expression match for a MAC format address of the associated mac
                if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", output2.lower()):
                    #add a match
                    self.count +=1
                    print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
                    print "KARMA ACCESSS POINT DETECTED"
                    print "Fake SSID ", fakeSSID
                    print "Association  SSID ", output
                    print "Association Rouge BSSid", output2
                    if output2 in self.KARMAAP:
                        print  "KARMA BSSSID Seen Before"
                    #store BAD access point
                    self.KARMAAP.append(output2)
                    print "KARMA Detected " + str(self.count) + " times"
                    print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

            # Test that all the KARMA access point are using the same BSSSID (if not still could just randomizes BSSID)
        result =  self.KARMAAP and all( self.KARMAAP[0] == elem for elem in  self.KARMAAP)
        print  "**********************************************************************************************"
        print  "Same KARMA Access Point in all instances " + str(result)
        print "\n\n"
        print "Restarting Services"
        
        
        os.system("sudo ifconfig wlan4 down" )
        os.system("sudo iwconfig wlan4 essid off")
        os.system("ifconfig wlan4 up")

        
        
        os.system("service network-manager start")
        os.system("dhclient")
        
        if self.count > 0:
            return {"count":self.count,"result":result,"BSSID":self.KARMAAP}
        else:
            return False

##main script start
if __name__ == '__main__':
    print None
    ##main stop interfering services and then start program
    #os.system("service network-manager stop")
    #k = karmaid()
    #k.fakeSSID()
    #
    #
    #print "\n\n"
    #print "Restarting Services"
    #os.system("service network-manager start")
    #os.system("dhclient")
    





