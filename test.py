#!/usr/bin/env python
# hello
import logging
import time
logging.getLogger("scapy").setLevel(1)
from scapy.all import *
import sys
import pylab
import matplotlib.pyplot as plt
beaconNumber = 0
x = []
y = []
firstBeaconObserved = 0
firstBeaconInternalTimer = 0

if len(sys.argv) != 2:
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
		firstBeaconObserved = 0
		if pkt.type == 0 and pkt.subtype == 8  and pkt.info == targetSSID:
			beaconNumber += 1
			if beaconNumber == 1:
			    firstBeaconObserved = pkt.timestamp
			    
			current = pkt.timestamp - firstBeaconObserved
			x.append(time.time() * CONV)
			oi = pkt.timestamp - (pkt.time * CONV)
			y.append(oi)
			print "beacon", beaconNumber
			print "sec",current
			print "radiotap",pkt.time
			print "TSF",pkt.timestamp
			print "offset",oi

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
				m, c = np.linalg.lstsq(A, y)[0]
				print "slope + c"
				print m, c
				print "attempt at root mean square"
				import statsmodels.api as sm				
				stacked = np.column_stack((np.ones(len(y)), np.array(y)))
				ols = sm.OLS(np.array(x), stacked).fit()
				predictions = ols.predict()
				def rmse(predictions, targets):
					return np.sqrt(((predictions - targets) ** 2).mean())				      
				print rmse(predictions,np.array(y))
				sys.exit(0)

sniff(iface="wlan4", prn = Handler)