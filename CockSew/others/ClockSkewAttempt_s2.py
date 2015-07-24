#!/usr/bin/env python
from pylab import *
import math
from decimal import * 
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
	  			firstBeaconObserved = pkt.time 
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
			elapasedTime = pkt.time -firstBeaconObserved
			print ""
			print "elapasedTime un mmod", elapasedTime
			unmod = elapasedTime

			elapasedTime = elapasedTime * CONV

			print "elapased time mod", elapasedTime


			elapasedTime2 = pkt.timestamp - firstBeaconInternalTimer

			print "elapased time from RadioTap", elapasedTime 
			print "elapasedTime from internal timestamp", elapasedTime2


			clockOffset = (elapasedTime2 - (elapasedTime))
			print "clockOffset", clockOffset 


			x.append(elapasedTime / CONV)
			y.append(clockOffset)

			#if beaconNumber == 150:	
			if unmod >= 15:	
				import numpy as np
				#import matplotlib.pyplot as plt
				#import matplotlib.pyplot as mpl
				#mpl.plot(x, y, label="Curve", color="blue", linestyle='-',linewidth=1)
				#mpl.grid(True)
				#mpl.xticks(np.arange(min(x), max(x)+1, 1.0))
				#mpl.xlabel('TIME')
				#mpl.ylabel('clock')
				#mpl.title("test")
				#mpl.legend()
				#mpl.show()

				# http://docs.scipy.org/doc/numpy/reference/generated/numpy.linalg.lstsq.html
				#print "least square"
				#A = np.vstack([x, np.ones(len(x))]).T
				## print A
				#m, c = np.linalg.lstsq(A, y)[0]
				#print "slope + c"
				#print m, c
				##print "m*x+c", (m*x + c)
				#
				#print "attempt at root mean square"
				#import statsmodels.api as sm				
				#stacked = np.column_stack((np.ones(len(y)), np.array(y)))
				#ols = sm.OLS(np.array(x), stacked).fit()
				#predictions = ols.predict()
				## print preds2	
				#def rmse(predictions, targets):
				#	return np.sqrt(((predictions - targets) ** 2).mean())				      
				#print rmse(predictions,np.array(y))
				
				print "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$"
				
				
				time = x
				position = y
				#Linear Fitting
				'''
				This calls the polyfit function (that is in the pylab module).
				Polyfit takes two variables and a degree. In this case the degree is 1 for a linear function.
				The results goes to the two variables m (for the slope) and b for the y-intercept of the equation y = mx + b.
				'''
				(m,b) = polyfit(time,position,1)
				print m, b
				
				'''
				This just evaluates the polynomial with the coefficients [m,b] and value x.
				So, for every x data point I have, this calculates a y value from the fitting function.
				Now I have a new set of values yp
				'''
				yp = polyval([m,b],time)
				print yp
				
				#model predicitons for each time
				model = []
				for i in range(len(time)):
				    val = Decimal(Decimal(time[i]) * Decimal(m)  + Decimal(b))
				    model.append(val)
				    #print val
				
				"residuals --- the difference between model prediction and the line"
				print "residuals"
				residuals = []
				residualsSquared = []
				for i in range(len(time)):
				    res = Decimal(Decimal(position[i]) - model[i])
				    residuals.append(res)
				    #print res
				    #print "squared", res * res
				    residualsSquared.append(res * res)
				
				"root mean square error calcuation"
				mean = Decimal(sum(residualsSquared)/len(residualsSquared))
				rmse = Decimal(math.sqrt(mean))
				
				print ""
				print "RMSE", rmse
				
				plot(time, yp)
				scatter(time, position)
				xlabel('time')
				ylabel('position')
				show()				
				
				
				
				sys.exit(0)

sniff(iface=ifaceno, prn = Handler)