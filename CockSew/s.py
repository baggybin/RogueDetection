#!/usr/bin/env python
# 7.39825300726
# 6.2865398499
 
import logging
import time
from scapy.all import *

import sys
import pylab
import matplotlib.pyplot as plt


beaconNumber = 0
x = []
y = []
firstBeaconObserved = 0
firstBeaconInternalTimer = 0


print "Start"

# os.system("hwclock -s")

def Handler(pkt) :
  global beaconNumber
  global firstBeaconObserved
  global firstBeaconInternalTimer
  
  CONV = 1000000
  if pkt.haslayer(Dot11):
  		# if pkt.type == 0 and pkt.subtype == 8  and pkt.info == "evil" and pkt.timestamp == 0:
  		# 	print "possible Airbase-ng AP"
  		# pineapple 

		if pkt.type == 0 and pkt.subtype == 8  and pkt.info == "Zoom":
			beaconNumber += 1
	  		if beaconNumber == 1:
	  			print "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
	  			#extremely inaccurate if use the radioTap Timer	  			
	  			firstBeaconObserved = time.time() 
	  			#firstBeaconObserved = pkt.time	  			
	  			firstBeaconInternalTimer = pkt.timestamp			
			
			print "BeaconNUmber" , beaconNumber
			print "@@@@@@@@@@@@@@@@@@@@@@@@@"
			print "AP MAC: %s with SSID: %s  %s" %(pkt.addr2, pkt.info, pkt.timestamp)
			print "AP Beacon frame timestamp", pkt.timestamp
			print "Arrival timestamp frame", pkt.time
#			print "first beacon observed locally", firstBeaconObserved
			print "first AP beacon internally frame ", firstBeaconInternalTimer


			# get the elapsed time since the first beacon was observed
			# attempt to normalize 
			elapasedTime = (time.time() * CONV) - (firstBeaconObserved * CONV)
			elapasedTime = time.time() -firstBeaconObserved
			print ""
			print "elapasedTime un mmod", elapasedTime

			elapasedTime = elapasedTime * 1000000

			print "elapased time mod", elapasedTime
			print ""

			elapasedTime2 = pkt.timestamp - firstBeaconInternalTimer

			print "elapased time from RadioTap", elapasedTime 
			print "elapasedTime from internal timestamp", elapasedTime2


			#d = {"beaconNumber":beaconNumber, "timeRX":pkt.time, "timeInFrame":pkt.timestamp,"elapased":elapasedTime, "elapased2":elapasedTime2}
			clockOffset = (elapasedTime2 - (elapasedTime))
			print "clockOffset", clockOffset 

			#d = {"beaconNumber":beaconNumber, "timeRX":pkt.time, "timeInFrame":pkt.timestamp,"elapased":elapasedTime, "elapased2":elapasedTime2}
			#clockset = {"id":beaconNumber ,"xi": elapasedTime, "yi":clockOffset}
			x.append(elapasedTime / 1000000)
			y.append(clockOffset)
			#bset.append(clockset)

			if beaconNumber == 100:
				import numpy as np
				import matplotlib.pyplot as plt
				# import matplotlib.pyplot as mpl
				# mpl.plot(x, y, label="Curve", color="blue", linestyle='-',linewidth=1)
				# # add a grid
				# mpl.grid(True)
				# # # use x and y limits
				# # mpl.ylim((0,1))
				# # mpl.xlim((0,1))
				# mpl.xticks(np.arange(min(x), max(x)+1, 1.0))
				# # mpl.yticks(pylab.arange(0,1.1,.1))
				# # add a division line 
				# # mpl.plot([1.0,0.0], [0.0,1.0],'k--')
				# # #plot the best operating point on the curve
				# # mpl.plot(x,y,'ro', label=" Point")
				# mpl.xlabel('TIME')
				# mpl.ylabel('clock')
				# mpl.title("test")
				# mpl.legend()
				# mpl.show()

				# http://docs.scipy.org/doc/numpy/reference/generated/numpy.linalg.lstsq.html
				A = np.vstack([x, np.ones(len(x))]).T
				print A
				m, c = np.linalg.lstsq(A, y)[0]
				print m, c
				# print "m*x+c", m*x + c
				def rmse(predictions, targets):
					return np.sqrt(((predictions - targets) ** 2).mean())

				print rmse(np.array(x),np.array(y))


				sys.exit(0)
				# plt.plot(x, y, 'o', label='Original data', markersize=10)
				# plt.plot(x, m*x + c, 'r', label='Fitted line')				
				# plt.legend()
				# plt.show()

 
sniff(iface="wlan2", prn = Handler)