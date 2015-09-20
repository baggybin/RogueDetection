#!/usr/bin/env python
#imports
import sys, os
from scapy.all import *
import subprocess
import re
'''
KARAMID Class TO gneerate randon SSID's and apply them to a local interface
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
            #gneerate a small 16 character sequence SSID Randomly 
            fakeSSID =''.join(random.choice('0123456789ABCDEF') for i in range(16))
            
            print "________________________________"
            print "Randomly Generated SSID ", fakeSSID
            print "setting to local interface"
            print "Initiaiting probe Request for ", fakeSSID
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
                    print "KARMA Dectected " + str(self.count) + " times"
                    print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

            # Test that all the KARMA acccess point are using the same BSSSID (if not stilll could just rnadomise BSSID)
        result =  self.KARMAAP and all( self.KARMAAP[0] == elem for elem in  self.KARMAAP)
        print  "**********************************************************************************************"
        print  "Same KARMA Acccess Point in all instanaces " + str(result)
        print "\n\n"
        print "Restarting Services"
        os.system("service network-manager start")
        os.system("dhclient")
        
        return self.count

##main script start
if __name__ == '__main__':
    print None
    ##main stop interfeering services and then start program
    #os.system("service network-manager stop")
    #k = karmaid()
    #k.fakeSSID()
    #
    #
    #print "\n\n"
    #print "Restarting Services"
    #os.system("service network-manager start")
    #os.system("dhclient")
    





