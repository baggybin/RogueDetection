#!/usr/bin/env python
 
import logging
import time
logging.getLogger("scapy").setLevel(1)

from scapy.all import *

import sys
import pylab
import matplotlib.pyplot as plt
import hello

beaconNumber = 0
x = []
y = []
firstBeaconObserved = 0
firstBeaconInternalTimer = 0

if len(sys.argv) != 3:
    print "Usage %s SSID" % sys.argv[0]
    sys.exit(1)

targetSSID = sys.argv[1]
ifaceno = sys.argv[2]

def Handler(pkt) :
  global beaconNumber
  global firstBeaconObserved
  global firstBeaconInternalTimer
  global x
  global y
  
  CONV = 1000000
  if pkt.haslayer(Dot11):
		if pkt.type == 0 and pkt.subtype == 8  and pkt.info == targetSSID:
			beaconNumber += 1
	  		if beaconNumber == 1:
			        #time stamp from radioTap header	  			
	  			firstBeaconObserved = time.time() * CONV
	  			#timestamp from beacon frame 			
	  			firstBeaconInternalTimer = pkt.timestamp			
			print "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"			
			print "BeaconNUmber" , beaconNumber
			print "AP MAC: %s with SSID: %s  %s" %(pkt.addr2, pkt.info, pkt.timestamp)
			print "AP Beacon frame timestamp", pkt.timestamp
			print "Arrival timestamp frame", pkt.time
 			print "first beacon observed locally", firstBeaconObserved
			print "first AP beacon internally frame ", firstBeaconInternalTimer
			# get the elapsed time since the first beacon was observed
			# attempt to normalize 
			elapasedTime = (time.time()*CONV) -firstBeaconObserved
			print ""
			print "elapased time mod", elapasedTime
			elapasedTime2 = pkt.timestamp - firstBeaconInternalTimer

			print "elapased time from RadioTap", elapasedTime 
			print "elapasedTime from internal timestamp", elapasedTime2


			clockOffset = (elapasedTime2 - (elapasedTime))
			print "clockOffset", clockOffset 

			x.append(elapasedTime / CONV)
			y.append(clockOffset)

			if beaconNumber == 150:	
			#if unmod >= 15:	
				import numpy as np
				import matplotlib.pyplot as plt
				import matplotlib.pyplot as mpl
				mpl.plot(x, y, label="Curve", color="blue", linestyle='-',linewidth=1)
				mpl.grid(True)
				mpl.xticks(np.arange(min(x), max(x)+1, 1.0))
				mpl.xlabel('TIME')
				mpl.ylabel('clock')
				mpl.title("test")
				mpl.legend()
				mpl.show()

				# http://docs.scipy.org/doc/numpy/reference/generated/numpy.linalg.lstsq.html
				print "least square"
				A = np.vstack([x, np.ones(len(x))]).T
				# print A
				m, c = np.linalg.lstsq(A, y)[0]
				print "slope + c"
				print m, c
				#print "m*x+c", (m*x + c)

				print "attempt at root mean square"
				import statsmodels.api as sm				
				stacked = np.column_stack((np.ones(len(y)), np.array(y)))
				ols = sm.OLS(np.array(x), stacked).fit()
				predictions = ols.predict()
				# print preds2	
				def rmse(predictions, targets):
					return np.sqrt(((predictions - targets) ** 2).mean())				      
				print rmse(predictions,np.array(y))
				sys.exit(0)

sniff(iface=ifaceno, prn = Handler)