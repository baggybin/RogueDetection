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

class ClockSkew:
    def __init__(self, target):
	self.beaconNumber = 0
	self.x = []
	self.y = []
	self.beacon = []
	self.firstBeaconObserved = 0
	self.firstBeaconInternalTimer = 0
	self.targetSSID = target
	self.ifaceno = "wlan4"
	self.switch = "1"
	self.amount = 30	
	self.rsme  = 0
	self.stop = "no"

    def getRSME(self):
	return self.rsme
	
    def Handler(self,frame):
      #conversion Constant for microseconds
      CONV = 1000000
      # is passed data is an 802.11 Frame start processing
      # test if frame has info (evevry 500 or so encoutered frame that raised attribute error)
      if frame.haslayer(Dot11):# and hasattr(frame.payload, "info"):
		    '''
		    test if 802.11 frame is a management frame(0) of subtype beacon (8)
		    and the SSID of the frame is the same as specified target
		    '''
		    try:
			if frame.type == 0 and frame.subtype == 8  and frame.info == self.targetSSID:
				#start beacon counter
				self.beaconNumber += 1
				self.beacon.append(self.beaconNumber)
				if self.beaconNumber == 1:
					'''
					time stamp from radioTap header which is timestamped
					by local mac80211 driver of card firmware
					64-bit counter with microsecond resolution
					-- storing the first encountered observation from target SSID -- 
					'''                             
					self.firstBeaconObserved = frame.time 
					'''
					timestamp from beacon frame which was inserted by TSF timer
					on remote access point at exact moment of transmission
					-- storing the first encountered observation from target SSID --
					'''
					self.firstBeaconInternalTimer = frame.timestamp    
				'''
				print values to system out - terminal - for testing 
				'''                  
				print "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"                      
				print "BeaconNUmber" , self.beaconNumber
				print "AP MAC: %s with SSID: %s  %s" %(frame.addr2, frame.info, frame.timestamp)
				print "AP Beacon frame timestamp", frame.timestamp
				print "Arrival timestamp frame", frame.time
				print "first beacon observed locally", self.firstBeaconObserved
				print "first AP beacon internally frame ", self.firstBeaconInternalTimer
				# get the elapsed time since the first beacon was observed
				# by subracting the first observed time from the current frames local timestamp
				LocalelapasedTime = frame.time - self.firstBeaconObserved
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
				RemotelapasedTime2 = frame.timestamp - self.firstBeaconInternalTimer
	
				print "elapased Time Local RadioTap", LocalelapasedTime 
				print "elapased from remote TSF timestamp", RemotelapasedTime2
				''' 
				calculate the offset between the the localelaped time in microseconds
				and the remote elapsed time in microseconds to obtain the clock offset for
				this beacon
				'''
				clockOffset = (RemotelapasedTime2 - (LocalelapasedTime))
				print "clockOffset", clockOffset 
				self.x.append(LocalelapasedTime / CONV)
				self.y.append(clockOffset)
	
				'''
				counter for either seconds passed 
				or the number of beacons that have been captured
				'''
		    except:
			pass
				
    def rmse_function(self):
	    import numpy as np
	    import matplotlib.pyplot as plt
	    # Linear Fitting
	    # Root Mean Square Error

	    # rename lists of times and offsets for readability                        
	    time = self.x
	    clockoset = self.y

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
	    #print yp
	    
	    #model predicitons for each time entry 
	    model = []
	    for i in range(len(time)):
		    #valure for current index is the time * by the slope and the y-intercept
		val = Decimal(Decimal(time[i]) * Decimal(m)  + Decimal(b))
		model.append(val)


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

	    self.rmse = Decimal(math.sqrt(mean))
	    print "RMSE", self.rmse
	    print "no beacons collected", self.beaconNumber
	    f = open('rmse.txt','w')
	    f.write(str(self.rmse))
	    f.close()
	    return self.rsme		    
	
    def overlordfuntion(self):
	sniff(iface=self.ifaceno, prn = self.Handler, count = 300, lfilter = lambda x:(x.haslayer(Dot11Beacon) or x.haslayer(Dot11ProbeResp)))
