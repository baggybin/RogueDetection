#! /bin/python
import random
import os




for i in range(20):
    fakeSSID =''.join(random.choice('0123456789ABCDEF') for i in range(16))
    print fakeSSID
    os.system("sudo ifconfig wlan4 down" )
    os.system("iwconfig wlan4 essid " + fakeSSID )
    os.system("ifconfig wlan4 up")
    
    #ROUGE = os.system("iwconfig wlan4 | grep 'ESSID:' | awk '{print $4}' | sed 's/ESSID://g' | sed 's/\"//g'")

    import subprocess
    output = subprocess.check_output("iwconfig wlan4 | grep 'ESSID:' | awk '{print $4}' | sed 's/ESSID://g' | sed 's/\"//g'",shell=True )
    print output
    
    #print "ROUGE" , output
    
    #MAC = os.system("sudo iwconfig wlan4 | grep \"Access Point:\' | awk '{print $6}' | cut -c 1-17")
    #
    #from subprocess import Popen, PIPE
    #
    #(stdout, stderr) = Popen(["sudo iwconfig","wlan4"], stdout=PIPE).communicate()
    #print stdout
    #
    
    #MAC = subprocess.call("sudo iwconfig wlan4",shell=False )
    #
    #print "MAC"
    
    #
    #class sniff(Thread):
    #    """Main Socket Reading Thread for the client"""
    #    def __init__(self, client, text_send, ctrl, caller, aes, sharedMem):
    #        """Initialize"""
    #        Thread.__init__(self)
    #        self.client = client
    #        self.caller = caller
    #        self.text_send = text_send
    #        self.ctrl = ctrl
    #        self.aes = aes
    #        self.sharedMem = sharedMem
    #        self.start()
    #
    #    def run(self):
    #        while True:
    #            






