#! /bin/python
import random
import os



fakeSSID =''.join(random.choice('0123456789ABCDEF') for i in range(16))


os.system("sudo ifconfig wlan4 down" )
os.system("sudo iw dev  essid " + fakeSSID )
os.system("ifconfig wlan4 up")
os.system("iw dev %s set channel %d" % ("wlan4", 1))

os.system("iwgetid -")