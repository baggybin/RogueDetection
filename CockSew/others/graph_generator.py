#!/usr/bin/env python
 
import logging
import time
logging.getLogger("scapy").setLevel(1)

from scapy.all import *

import sys
import pylab
import matplotlib.pyplot as plt


ap_list = []
beaconNumber = 0
x = []
y = []
bset = []
firstBeaconObserved = 0
firstBeaconInternalTimer = 0

if len(sys.argv) != 3:
    print "Usage %s SSID" % sys.argv[0]
    sys.exit(1)

targetSSID = sys.argv[1]

def Handler(pkt) :
  global beaconNumber
  global firstBeaconObserved
  global firstBeaconInternalTimer
  global x
  global y
  
  CONV = 1000000
  if pkt.haslayer(Dot11):
  		# if pkt.type == 0 and pkt.subtype == 8  and pkt.info == "evil" and pkt.timestamp == 0:
  		# 	print "possible Airbase-ng AP"
  		# pineapple 

		if pkt.type == 0 and pkt.subtype == 8  and pkt.info == targetSSID:
			beaconNumber += 1
	  		if beaconNumber == 1:
	  		    # time stamp from radioTap header	  			
	  			firstBeaconObserved = pkt.time 
	  			#firstBeaconObserved = pkt.time	  
	  			# timestamp from beacon frame 			
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
			elapasedTime = pkt.time -firstBeaconObserved
			print ""
			print "elapasedTime un mmod", elapasedTime
			unmod = elapasedTime

			elapasedTime = elapasedTime * 1000000

			print "elapased time mod", elapasedTime
			print ""

			elapasedTime2 = pkt.timestamp - firstBeaconInternalTimer

			print "elapased time from RadioTap", elapasedTime 
			print "elapasedTime from internal timestamp", elapasedTime2


			clockOffset = (elapasedTime2 - (elapasedTime))
			print "clockOffset", clockOffset 

			#d = {"beaconNumber":beaconNumber, "timeRX":pkt.time, "timeInFrame":pkt.timestamp,"elapased":elapasedTime, "elapased2":elapasedTime2}
			clockset = {"id":beaconNumber ,"xi": elapasedTime, "yi":clockOffset}

			x.append(elapasedTime / 1000000)
			y.append(clockOffset)
			bset.append(clockset)

			if beaconNumber == 300:	
			#if unmod >= 15:	
				import numpy as np
				import matplotlib.pyplot as plt
				import matplotlib.pyplot as mpl
				mpl.plot(x, y, label="Curve", color="blue", linestyle='-',linewidth=1)
				# add a grid
				mpl.grid(True)
				# # use x and y limits
				# mpl.ylim((0,1))
				# mpl.xlim((0,1))
				mpl.xticks(np.arange(min(x), max(x)+1, 1.0))
				# mpl.yticks(pylab.arange(0,1.1,.1))
				# add a division line 
				# mpl.plot([1.0,0.0], [0.0,1.0],'k--')
				# #plot the best operating point on the curve
				# mpl.plot(x,y,'ro', label=" Point")
				mpl.xlabel('Seconds')
				mpl.ylabel('Microsecond Clock Drift')
				mpl.title("Clock Skew")
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
				# plt.plot(x, y, 'o', label='Original data', markersize=10)
				# plt.plot(x, m*x + c, 'r', label='Fitted line')				
				# plt.legend()
				# plt.show()

sniff(iface="wlan4", prn = Handler)
