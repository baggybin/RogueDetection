#!/bin/python

import datetime

'''
Class rougelog:

Custom Log enteries to a file
'''

class rougelog:
    def __init__(self):
	pass

    def detectedkarma(self, BSSID ,Amount,single, level):
	f=open("ROUGE.LOG","a")
	msg = "KARMA Access Point Detection"
	log=str(datetime.datetime.today())+" |Severity "+ str(level) + " |MESSAGE " +str(msg)+ " |BSSID " +str(BSSID)+ " |Times "+str(Amount)+" |Single AP "+str(single)+"\n"
	f.write(log)
	f.close()

    def beginlog(self):
	f=open("ROUGE.LOG","a")
	log="**************************************\nSTARTING CAPTURE ON "+str(datetime.datetime.today())+"\n**************************************\n"
	f.write(log)
	f.close()
	
    def detectedAIRBASE(self, SSID, Channel, level=3):
	f=open("ROUGE.LOG","a")
	msg = "Possible Airbase-NG Access Point Detection"
	log=str(datetime.datetime.today())+" |Severity "+ str(level) + " |MESSAGE " +str(msg)+ " |SSID " +str(SSID)+ " |Channel "+str(Channel)+"\n"
	f.write(log)
	f.close()
		
    def channelChange(self, SSID, BSSID, Channel, level=2):
	f=open("ROUGE.LOG","a")
	msg = "Channel Change "
	log=str(datetime.datetime.today())+" |Severity "+ str(level) + " |MESSAGE " +str(msg)+ " |SSID " + str(SSID)+ " |BSSID " +str(BSSID)+ " |Channel "+str(Channel)+"\n"
	f.write(log)
	f.close()
	
    def Invalid_OUI(self, SSID, BSSID, Channel, level=7):
	f=open("ROUGE.LOG","a")
	msg = "Invalid OUI Code "
	log=str(datetime.datetime.today())+" |Severity "+ str(level) + " |MESSAGE " +str(msg)+ " |SSID " + str(SSID)+ " |BSSID " +str(BSSID)+ " |Channel "+str(Channel)+"\n"
	f.write(log)
	f.close()
	
    def general(self,msg1, SSID, BSSID, Channel, level=7):
	f=open("ROUGE.LOG","a")
	msg = msg1
	log=str(datetime.datetime.today())+" |Severity "+ str(level) + " |MESSAGE " +str(msg)+ " |SSID " + str(SSID)+ " |BSSID " +str(BSSID)+ " |Channel "+str(Channel)+"\n"
	f.write(log)
	f.close()	
	
	
#log = rougelog()
#log.beginlog()
#log.detectedkarma("aa:bb:cc:dd:ee:ff",3,True,10)



