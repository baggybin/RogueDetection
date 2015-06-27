#!/usr/bin/env python
# library imports
from pylab import *
import math
from decimal import * 
import logging
import time 
from scapy.all import *
import sys
import pylab
import matplotlib.pyplot as plt
import simplejson

from json import dumps, loads, JSONEncoder, JSONDecoder
import pickle

class PythonObjectEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (list, dict, str, unicode, int, float, bool, type(None))):
            return JSONEncoder.default(self, obj)
        return {'_python_object': pickle.dumps(obj)}

def as_python_object(dct):
    if '_python_object' in dct:
        return pickle.loads(str(dct['_python_object']))
    return dct

# storage vaiables and lists
beaconNumber = 0
x = []
y = []
beacon = []
firstBeaconObserved = 0
firstBeaconInternalTimer = 0

# take arguments from the command line
if len(sys.argv) != 5:
    print "%s - SSID wlanx switch amount" % sys.argv[0]
    sys.exit(1)

# Target SSID and Local Operating Interface
# taken as arugments from command line
targetSSID = sys.argv[1]
ifaceno = sys.argv[2]
switch = sys.argv[3]
amount = int(sys.argv[4])


def Handler(frame) :
  # access to global variables
  # only for convenience in script
  global beaconNumber
  global firstBeaconObserved
  global firstBeaconInternalTimer
  global x
  global y
  global beacon
  global switch
  
  #conversion Constant for microseconds
  CONV = 1000000
  # is passed data is an 802.11 Frame start processing
  # test if frame has info (evevry 500 or so encoutered frame that raised attribute error)
  if frame.haslayer(Dot11):# and hasattr(frame.payload, "info"):
  		'''
		test if 802.11 frame is a management frame(0) of subtype beacon (8)
		and the SSID of the frame is the same as specified target
		'''
		if frame.type == 0 and frame.subtype == 8  and frame.info == targetSSID:
			#start beacon counter
			beaconNumber += 1
			beacon.append(beaconNumber)
			if beaconNumber == 1:
				'''
				time stamp from radioTap header which is timestamped
				by local mac80211 driver of card firmware
				64-bit counter with microsecond resolution
				-- storing the first encountered observation from target SSID -- 
				'''                             
				firstBeaconObserved = frame.time 
				'''
				timestamp from beacon frame which was inserted by TSF timer
				on remote access point at exact moment of transmission
				-- storing the first encountered observation from target SSID --
				'''
				firstBeaconInternalTimer = frame.timestamp    
			'''
			print values to system out - terminal - for testing 
			'''                  
			print "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"                      
			print "BeaconNUmber" , beaconNumber
			print "AP MAC: %s with SSID: %s  %s" %(frame.addr2, frame.info, frame.timestamp)
			print "AP Beacon frame timestamp", frame.timestamp
			print "Arrival timestamp frame", frame.time
			print "first beacon observed locally", firstBeaconObserved
			print "first AP beacon internally frame ", firstBeaconInternalTimer
			# get the elapsed time since the first beacon was observed
			# by subracting the first observed time from the current frames local timestamp
			LocalelapasedTime = frame.time - firstBeaconObserved
			print "LocalelapasedTime", LocalelapasedTime
			#store seconds
			secondsCounter = LocalelapasedTime
			# convert the the local elapsedTime to microseconds
			LocalelapasedTime = LocalelapasedTime * CONV
			print "elapased time microseconds", LocalelapasedTime

			'''
			calucate the difference between first TSF timer of original beacon
			and the timestamp of the current beacon
			'''
			RemotelapasedTime2 = frame.timestamp - firstBeaconInternalTimer

			print "elapased Time Local RadioTap", LocalelapasedTime 
			print "elapased from remote TSF timestamp", RemotelapasedTime2
			''' 
			calculate the offset between the the localelaped time in microseconds
			and the remote elapsed time in microseconds to obtain the clock offset for
			this beacon
			'''
			clockOffset = (RemotelapasedTime2 - (LocalelapasedTime))
			print "clockOffset", clockOffset 
			x.append(LocalelapasedTime / CONV)
			y.append(clockOffset)

			'''
			counter for either seconds passed 
			or the number of beacons that have been captured
			'''
			if secondsCounter >= amount and switch == "1" or beaconNumber >= amount and switch == "0":        
				import numpy as np
				import matplotlib.pyplot as plt
				# Linear Fitting
				# Root Mean Square Error

				# rename lists of times and offsets for readability                        
				time = x
				clockoset = y

				'''
				Linear Fitting for finding the slope and line through observed clock
				offsets, a line that is a close to all the clock offsets as possible.
				Find the line of best fit which minimses the sum of the squares of the residuals
				'''

				'''
				This calls the polyfit function, a pylab module.
				Polyfit takes two lists and a degree. In this case the degree is 1 for a linear function.
				The results are stored in two variables m (slope) and b (y-intercept) of the equation 
				y = mx + b.
				'''		
				(m,b) = polyfit(time,clockoset,1)
				print m, b
				
				'''
				Evaluates the polynomial with the coefficients [m,b] and the list time.
				So, for every time data point, a y value is calculated from the fitting function.
				creating a set of values yp
				'''
				yp = polyval([m,b],time)
				print yp
				
				#model predicitons for each time entry 
				model = []
				for i in range(len(time)):
					#valure for current index is the time * by the slope and the y-intercept
				    val = Decimal(Decimal(time[i]) * Decimal(m)  + Decimal(b))
				    model.append(val)


				import matplotlib.pyplot as mpl
				mpl.plot(x, y, label="offset", color="red", linestyle='-',linewidth=1)
				mpl.plot(time, yp, label="linear regression", color="blue")
				# add a grid
				mpl.grid(True)
				# set the max for the xsis (neatness)
				mpl.xlim(xmax=int(max(x)))
				# arrange ticks for x axis
				mpl.xticks(np.arange(min(x), int(max(x)) + 1, 1.0))
				mpl.xlabel('Seconds')
				mpl.ylabel('Microsecond Offset')
				# title is the SSID
				mpl.title(frame.info)
				mpl.legend()
				mpl.show()

				
				'''
				residuals --- 
				the difference between model predictions of the linear fit line
				and the observed clock offset values

				use squares to convert all values to positve values
				'''
				residuals = []
				residualsSquared = []
				for i in range(len(time)):
					# at each index subract the model value from the 
					# observed clock offset at this index
				    res = Decimal(Decimal(clockoset[i]) - model[i])
				    # store the residual and 
				    # store the squared value of the residual
				    residuals.append(res)
				    residualsSquared.append(res * res)
				
				'''
				root mean square error calcuation.
				calculate the mean of the sqaured residuals by adding them 
				together and diving by the total number of residuals
				'''
				mean = Decimal(sum(residualsSquared)/len(residualsSquared))
				#finally calculate the square root of the mean 
				#to generate the Root Mean Squared Error
				rmse = Decimal(math.sqrt(mean))
				print "RMSE", rmse
				
				# plot the scatter for testing
				# pylab.xlim(xmin=0)
				# plt.grid(True)

				# #force beacons
				# switch = "0"
				# if switch == "0":	
				# 	pylab.xlim(xmin=1)
				# 	plt.scatter(beacon, clockoset)
				# 	plt.plot(beacon, yp)
				# else:
				# 	pylab.xlim(xmin=0)
				# 	pylab.xlim(xmax=int(max(time)))
				# 	plt.scatter(time, clockoset)
				# 	plt.plot(time, yp)				
				
				
				# label = "Seconds"
				# if switch == "0":
				# 	label = "Beacons"
				# 	plt.xticks(np.arange(min(beacon) - 1, max(beacon) + 10, 10.0))
				# else:
				# 	#plt.xticks(np.arange(min(x), max(x), 1.0))	
				# 	plt.xticks(np.arange(min(x), int(max(x)) + 1, 1.0))	

				# plt.xlabel(label)
				# plt.ylabel('Microsecond offset')
				# plt.show() 

				d = {"rmse": rmse, "ssid": frame.info, "m": m, "b": b, "yp" : yp, "x":x, "y":y ,"beaconNumber": beaconNumber, "secondsCounter": secondsCounter, "bssid": frame.addr2}

				f = open('output.txt', 'w')
				j = dumps(d, cls=PythonObjectEncoder)
				f.write(j) 
				print "no beacons collected", beaconNumber                       
				sys.exit(0)

sniff(iface=ifaceno, prn = Handler)
