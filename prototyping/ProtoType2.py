import sys
from multiprocessing import Process
from scapy.all import *
import binascii
import os
from threading import Thread
from subprocess import Popen
import time
from netaddr import *
import manuf
import math
import threading
from wifi import Cell, Scheme
from tinydb import TinyDB, where
import logging
logger = logging.getLogger('ProtoType2.py')
hdlr = logging.FileHandler("RougeID.log")
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
logger.setLevel(logging.WARNING)
from iw_karma_detect import *
from clock_skew_main1 import *
from subprocess import check_output
from decimal import *
from test_channel_change import *
from termcolor import colored
from binascii import *
from scapy.all import *
import signal
#https://github.com/ivanlei/airodump-iv/blob/master/airoiv/scapy_ex.py
import scapy_ex
import wx
from wx.lib.pubsub import pub

'''
working very very slowly

same BSSID but different other attributes such as encyption, channnel

same AP ESSID with different BSSID

OUI

'''
class scanning:
    """Class for a user of the chat client."""
    def __init__(self, intf, count, channel,BSSID, SSID, accesspoint, database):
        self.intf = intf
        self.BSSID = BSSID
        self.SSID = SSID
        self.accesspoint = accesspoint
        self.seq1 = 0
        self.flag1 = 0
        self.counter = 0
        self.channel = accesspoint["channel"]
        self.count = count
        self.accessPointsSQ = []
        self.seq_list = []
        self.time_seq = []
        self.appearanceCounter = 0
        self.database = database
        self.flag_remove = 0
        self.stop_sniff = False
    
    
    def channel_change(self, ssid):
        os.system("sudo ifconfig %s down" %  self.intf )
        os.system("sudo iw dev "+  self.intf + " set type monitor")
        os.system("sudo ifconfig %s up" %  self.intf )
        try:
            os.system("sudo iw dev %s set channel %d" % (self.intf, self.channel))
            print colored("+++++++++++++++++++++++++++++++++++++channel Change-----------------------------","yellow"), self.channel
            print colored("+++++++++++++++++++++++++++++++++++++","yellow"), ssid
        except Exception, err :
               print err 
    
    # decorator to make system call methods safe from EINTR
    def systemcall(self, meth):
        # have to import this way to avoid a circular import
        from _socket import error as SocketError
        def systemcallmeth(*args, **kwargs):
            while 1:
                try:
                        rv = meth(*args, **kwargs)
                except EnvironmentError as why:
                    if why.args and why.args[0] == EINTR:
                        continue
                    else:
                        raise
                except SocketError as why:
                    if why.args and why.args[0] == EINTR:
                        continue
                    else:
                        raise
                else:
                    break
            return rv
        return systemcallmeth
    
    def set_ch(self, channel):
        self.channel = channel
        
    def check_rm(self):
        return self.flag_remove
    
    def ch_hop(self, channel, ssid):
           try:
               os.system("sudo ifconfig %s down" %  self.intf )
               os.system("sudo iw dev "+  self.intf + " set type monitor")
               os.system("sudo ifconfig %s up" %  self.intf ) 
               os.system("sudo iw dev %s set channel %d" % (self.intf, channel))
               print colored("-----------------------------channel Change-----------------------------","yellow"), channel
               print colored("-----------------------------SSID-----------------------------","yellow"), ssid
           except Exception, err :
               print err  


    def checkTheSeq(self, li):
        start=int(li[0])
        for e in li[1:]:
            a=int(e)
            if a > start:
                start=a
            else:
                return False
        return True
    
    
    def oui(self, frame):
        result = False
        p = manuf.MacParser()
        test = p.get_all(frame.lower())
        if test.manuf is not None:
            print colored("Real Manufacture OUI Code", "yellow")
            result = True
        return result

    
    def stop_sniffing(self, signal, frame):
        self.stop_sniff = True
        self.__del__()
        
    #def __del__(self):
    #    print 'died'        
        
    def keep_sniffing(self, pckt):
        return self.stop_sniff
       
    def sniffAP(self):
        print "------------------Started-----------------------------------------------"
        def PacketHandler(frame):
          try:     ##crosstalk with out filtering .info
            
            essid = pckt[Dot11Elt].info if '\x00' not in pckt[Dot11Elt].info and pckt[Dot11Elt].info != '' else 'Hidden SSID'
            print "Hidden Test", essid
            
            if frame.haslayer(Dot11) and frame.type == 0 and frame.subtype == 8 and not frame.info == self.accesspoint["ssid"]:
                self.appearanceCounter +=1
                if self.appearanceCounter > 5:
                    #print "Appears to be offline"
                    #choice = str(raw_input("Remove Acccess Point y/n \n"))
                    #if choice == "y" or choice == "Y":                   
                    #    self.flag_remove = 1
                    return
                return
            
            
            if frame.haslayer(Dot11) and frame.type == 0 and frame.subtype == 8 and frame.info == self.accesspoint["ssid"]:           
              self.appearanceCounter = 0
              #try:
              #   extra = frame.notdecoded
              #except:
              #   extra = None
              #if extra!=None:
              #   #signal_strength = -(256-ord(extra[-4:-3]))
              #   #signal_strength = -(256-ord(extra[14:15]))
              #   signal_strength = frame.dBm_AntSignal
              #else:
              #   signal_strength = -100
              #   print "No signal strength found"              
              #### not much use as scanning the one channel
              #try:
              #    val = self.datab.search((where('ssid') == str(frame.info)))
              #    #print "$$$$$$$$$$$$$$$$$$$    VAL    $$$$$$$$$$$$$$$$$$$$$$$$$$$$$"
              #    #print val, frame.info
              #    ch = int(ord(frame[Dot11Elt:3].info))
              #    if not ch == val["channel"]:
              #        print "Channel Has changed"
              #except:
              #    pass    
              if not frame.Channel == self.accesspoint["channel"]:
                  print colored("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", "pink")
                  print "Channel Has been Changed"
                  print colored("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", "pink")                
              signal_strength = frame.dBm_AntSignal
              #operating_channel = frame.notdecoded
              #data = frame.notdecoded[12:13]
              #binascii.hexlify(data)
              #int(ord(binascii.hexlify(data)),16)      
              
              enc = None
              if self.flag1 == 0:
                  result = self.oui(frame.addr2)
                  print colored("*******************    OUI ", "blue"),result
                  self.flag1 = 1
                  if result == False:
                    print colored("Not a Manufactures OUI Code ", "red"),result
                    logger.error("Not a Manufactures OUI Code " + frame.info + " BSSID " + frame.addr2 ) 
                  ## direcly from Airoscapy
                  capability = frame.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                  {Dot11ProbeResp:%Dot11ProbeResp.cap%}")
                  # Check for encrypted networks
                  if re.search("privacy", capability):
                      enc = True
                  else:
                      enc = False
                  if not self.accesspoint["encrypted"] == enc:
                      print colored("the encrpytion has changed", "red")
                      logger.error("the encrpytion has changed for " + frame.info)
                     
                    
                      
                      #Android randomises mac
              if not self.accesspoint["address"].lower() == frame.addr2 and not frame.info =="AndroidAP":
                  print colored("BSSID Adresss has been chnaged", "red")
                  print colored("OR crossralk, or System that uses random MACS like Android","yellow"), frame.info
                  print frame.info
                  print frame.addr2
                  print self.accesspoint["address"]
                  print self.accesspoint["address"].lower()
              
              if not self.accesspoint["address"].lower() == frame.addr2 and frame.info =="AndroidAP":
                  print colored("Android Software access Point Operating", "red")
                  print colored("OR crossralk, or System that uses random MACS like Android","yellow"), frame.info
                  print frame.info
                  print frame.addr2
                  print self.accesspoint["address"]
                  print self.accesspoint["address"].lower()             
              
                
              try:
                  if frame.info == self.SSID or self.BSSID.lower() == frame.addr2:
                      try:
                          self.seq1 = frame.SC
                          self.seq_list.append(frame.SC)
                          self.time_seq.append(frame.timestamp)
                          self.counter += 1
                          if self.counter == 25:
                              print "RSSI for ", frame.info, signal_strength 
                              print colored("++++++++++++++++++++++ 25 Sequenecec Numbers Collected", "yellow")
                              print colored("++++++++++++++++++++++ Analyzing +++++++++++++++++++++", "yellow")
                              val = self.checkTheSeq(self.seq_list)
                              print colored("++++++++++++++++++++++ Sequence","magenta"), val
                              if val == False:
                                  print colored("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< Possible Evil Twin Invalid OUI >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> ", "red")
                              if not self.BSSID.lower() == frame.addr2:
                                  print colored("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< Possible Evil Twin Adddress Change >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> ", "red")       
                              self.seq_list = []
                              
                              result_timestamp = self.checkTheSeq(self.time_seq)
                              if result_timestamp == False:
                                  print "$$$$$$$$$$$$$$$     Timestamp Sequence Change"
                              
                              self.counter = 0
                              result = self.oui(frame.addr2)
                              print colored("******************** OUI ", "red"), result
                              if result == False:
                                  print colored("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< Possible Mac Spoof >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> ","red")
                          self.accessPointsSQ.append(frame.SC)
                      except  Exception,e:
                          print "error", e
              except:
                  pass
          except Exception, e:
                pass
        #signal.signal(signal.SIGINT, self.stop_sniffing)
        sniff(iface=self.intf, count = self.count, prn=PacketHandler, store=0,timeout = 10,lfilter = lambda x:(x.haslayer(Dot11Beacon) or x.haslayer(Dot11ProbeResp)), stop_filter=self.keep_sniffing )

    
# lyre
# "C0:4A:00:E4:B6:70"
# zoom1
# "00:50:18:66:89:D6"
########################################################################################################################################

class modes:
    """Class for a user of the chat client."""
    def __init__(self):
        self.karmaDetecetection = {}
        self.airbaseNG_Detection = {}
        self.db = TinyDB('db.json')
    
    def get_db(self):
        return self.db
        
    def KARMA_PROBE(self):
        k = karmaid()
        val = k.fakeSSID()
        print "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
        print "karma", val["count"], "detected"
        print "BSSID ", val["result"], "same"
        print "BSSID", val["BSSID"]
        print "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
        
    def airbaseNG_manual(self):
        m_channnel = int(input("Enter Channel: "))
        print "-----------------------------------------"
        m_ssid = str(raw_input("Enter SSID: "))
        print "-----------------------------------------"
    
        chann_change(m_channnel)

        clock = ClockSkew(str(m_ssid))
        clock.overlordfuntion()
        value = clock.rmse_function()
        time.sleep(1)
        f = open('rmse.txt','r')
        val3 = f.read()
        f.close()
        
        #'print "value", value
        if Decimal(val3) > Decimal(299):     
           print colored("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^", "red")
           print colored("Possible AIRBASE-NG Software Based Access Point","red")
           print colored("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^", "red")    
        else:
          print "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
          print colored("<<<<<<<<<<<<    Not AirBase-NG   <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<", "yellow")
          print ""    
    
    
    
    def airbaseNG_secondAttempt(self):
       import subprocess 
       import re 
       self.managed() 
       proc = subprocess.Popen('iwlist wlan4 scan', shell=True, stdout=subprocess.PIPE, ) 
       stdout_str = proc.communicate()[0] 
       stdout_list=stdout_str.split('\n') 
       essid=[] 
       address=[]
       channel=[]
       for line in stdout_list: 
            line=line.strip() 
            match=re.search('ESSID:"(\S+)"',line) 
            if match: 
                essid.append(match.group(1)) 
            match=re.search('Address: (\S+)',line) 
            if match: 
                address.append(match.group(1))
                
            match = re.search('Channel:([0-9]+)',line)
            if match:
                channel.append(match.group(1))
                
       print essid 
       print address
       print channel
       
       count = 0
       for s in essid:
            print s , count 
            count +=1
       
       c = int(input("Enter Choice: "))
       print "-----------------------------------------"

    
       chann_change(channel[c])

       clock = ClockSkew(str(essid[c]))
       clock.overlordfuntion()
       value = clock.rmse_function()
       time.sleep(1)
       f = open('rmse.txt','r')
       val3 = f.read()
       f.close()
        
        #'print "value", value
       if Decimal(val3) > Decimal(299):     
           print colored("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^", "red")
           print colored("Possible AIRBASE-NG Software Based Access Point","red")
           print colored("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^", "red")    
       else:
          print "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
          print colored("<<<<<<<<<<<<    Not AirBase-NG   <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<", "yellow")
          print "" 
       
       
       

    
    def airbaseNG(self):
        self.managed()
        ce = Cell.all("wlan4")
        s = []
        count = 0
        
        
        #
        proc = subprocess.Popen('iwlist wlan4 scan', shell=True, stdout=subprocess.PIPE, ) 
        stdout_str = proc.communicate()[0] 
        stdout_list=stdout_str.split('\n') 
        essid=[] 
        address=[]
        for line in stdout_list: 
            line=line.strip() 
            match=re.search('ESSID:"(\S+)"',line) 
            if match: 
                essid.append(match.group(1)) 
            match=re.search('Address: (\S+)',line) 
            if match: 
                address.append(match.group(1))                
        # temp fix
        pos = 0
        missing = ""
        place = 0
        for c in ce:
            if c.ssid == "":
                if essid[pos] not in ce:
                    print colored("!!!!!!!!!Airbase-NG error Sending empty SSID simultaneously!!!!!!!!! SSID\n", "red")
                    print colored("!!!!!!!!!missing!!!!!!!!! SSID\n", "red"), essid[pos], "count ", pos , "\n"
                    print colored("!!!!!!!!!Substition for Null ssid may work\n", "yellow")
                    missing = essid[pos]
                    place = pos
                    break
            pos += 1
        
        print essid
        #
        #
        #
        #
        #
        #for c in ce:
        #    count += 1    
        #    if flag_missing == True:
        #        if place +1 == count:
        #            print ":"+ str(count), " ssid:", essid[place+1]
        #        else:
        #            print ":"+ str(count), " ssid:", c.ssid
        #            #create dictionary with informnation on the accesss point
        #        SSIDS = {"no" : count ,"ssid": c.ssid, "channel":c.channel,"encrypted":c.encrypted, \
        #                    "frequency":c.frequency,"address":c.address, "signal":c.signal, "mode":c.mode}
        #            #append this dictionary to a list
        #        s.append(SSIDS)        
        #    else:
        #        print ":"+ str(count), " ssid:", c.ssid
        #            #create dictionary with informnation on the accesss point
        #        SSIDS = {"no" : count ,"ssid": c.ssid, "channel":c.channel,"encrypted":c.encrypted, \
        #                    "frequency":c.frequency,"address":c.address, "signal":c.signal, "mode":c.mode}
        #            #append this dictionary to a list
        #        s.append(SSIDS)
                
        for c in ce:
            count += 1    
            print ":"+ str(count), " ssid:", c.ssid
                #create dictionary with informnation on the accesss point
            SSIDS = {"no" : count ,"ssid": c.ssid, "channel":c.channel,"encrypted":c.encrypted, \
                        "frequency":c.frequency,"address":c.address, "signal":c.signal, "mode":c.mode}
                #append this dictionary to a list
            s.append(SSIDS)
                        
                
        input_var = int(input("Choose: "))
        print "-----------------------------------------"
        target = s[input_var - 1]
        
        
        
        chann_change(target["channel"])
        #targetSSID , ifaceno, switch, amount
        
        if target["ssid"] == "":
            clock = ClockSkew(missing)
        else:
            clock = ClockSkew(target["ssid"])
            
        clock.overlordfuntion()
        value = clock.rmse_function()
        time.sleep(1)
        f = open('rmse.txt','r')
        val3 = f.read()
        f.close()
        
        #'print "value", value
        if Decimal(val3) > Decimal(299):     
           print colored("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^", "red")
           print colored("Possible AIRBASE-NG Software Based Access Point","red")
           print colored("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^", "red")    
        else:
          print "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
          print colored("<<<<<<<<<<<<    Not AirBase-NG   <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<", "yellow")
          print ""    
    
    
    def white_listing(self):
        interface = str(raw_input("Choose Interface for monitor: "))
        os.system("sudo ifconfig %s down" %  interface)
        os.system("sudo iwconfig "+  interface + " mode managed")
        os.system("sudo ifconfig %s up" %  interface )
        cell = Cell.all(interface)
        #b = TinyDB('db.json')
        #db.purge()
        Auth_AP = {}
        S = []
        #have a counter for user choice input
        count = 0
        for c in cell:
            count += 1
            print ":"+ str(count), " ssid:", c.ssid
                #create dictionary with informnation on the accesss point
            SSIDS = {"no" : count ,"ssid": c.ssid, "channel":c.channel,"encrypted":c.encrypted, \
                        "frequency":c.frequency,"address":c.address, "signal":c.signal, "mode":c.mode}
                #append this dictionary to a list
            S.append(SSIDS)
        ## get choice from the user
        input_var = int(input("Choose: "))
        print "---------------------------------------------"
        ap = S[input_var - 1]
        print ap["ssid"]
        print ap["address"]
        print ap["encrypted"]
        print ap["channel"]
        print "---------------------------------------------"
        
        loop = True
        while loop:
            try:
                input_var = int(input("1: Store Valid AP \n2: Disregard and Continue\n:"))     
                if input_var > 0 and input_var <= 2:
                    loop = False
            except ValueError:
                pass
        
        if input_var == 1:
            #db.purge()
            if self.db.search((where('ssid') == ap["ssid"]) & (where('address') == str(ap["address"]))) == []:
                self.db.insert(ap)
            else:
                print colored("!!!!!!!!!! already Stored in the database", "red")
            #print all database
            print self.db.all()
    
    def chann_change(self, channel):
        os.system("sudo ifconfig %s down" % "wlan4" )
        os.system("sudo iw dev "+ "wlan4" + " set type monitor")
        os.system("sudo ifconfig %s up" %  "wlan4")
        try:
            os.system("sudo iw dev %s set channel %d" % ("wlan4", channel))
            print "channel Change", channel
            print ""
        except Exception, err :
               print err
               
    def managed(self):
        os.system("sudo ifconfig %s down" % "wlan4" )
        os.system("sudo iw dev "+ "wlan4" + " set type managed")
        os.system("sudo ifconfig %s up" %  "wlan4")
        
    def purge_db(self):
        self.db.purge()
        return True
    
    
    def Rouge_IDS(self):
        loop = True
        while loop:
            flag = 0
            for ap in self.db.all():
                    try:
                        print colored("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^", 'red')
                        print "$$$$$$$$$$$$$$$$$$$$$$$   Now Sannning -----> " , ap["ssid"]
                        print colored("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^", 'red')
                        s = scanning(intf="wlan4", count = 100, channel=ap["channel"], BSSID=ap["address"],SSID=ap["ssid"], accesspoint=ap, database=self.db)                      
                       
                        if flag == 1:
                            for i in xrange(1, 3):
                                ch = random.randrange(1,11)
                                s.set_ch(ch)
                                s.ch_hop(ch, ap["ssid"])
                                s.sniffAP()
                                if i == 2:
                                    flag = 0
                         
                        if flag == 0:
                            s.set_ch(ap["channel"])
                            s.channel_change(ap["ssid"])
                            flag = 1                   
                        
                        s.sniffAP()
                        
                        if s.check_rm() == 1:
                            self.db.remove(where("ssid") == ap["ssid"])
                          
                    except KeyboardInterrupt, err:
                        print(traceback.format_exc())
                        print "interupted"                                         
            loop = False
 
 
 
 
from subprocess import *       
def main():
    m = modes()
    loop = True
    while loop:
        input_var = int(input(colored("1: Scan for Karma Access Points \n2: Scan a target to determine Airbase-NG \n3: Manually Scan a target to determine Airbase-NG  \n4: Try other attempt Airbase-NG  \n5: Enter Whitelist AP \n6: Start Wireless IDS \n7: System Exit \n:>", "yellow")))
        if input_var < 0 and input_var >7:
            pass
        elif input_var == 1:
            result = m.KARMA_PROBE()
        elif input_var == 2:
            val = m.airbaseNG()
        elif input_var == 3:
            val = m.airbaseNG_manual()
        elif input_var == 4:
            val = m.airbaseNG_secondAttempt()             
        elif input_var == 5:
            m.white_listing()
        elif input_var == 6:
            #Rouge_IDS()
            db = m.get_db()
            Rouge_IDS = Rouge_IDS_Background(db, False)
            #subprocess.Popen([sys.executable, Rouge_IDS.start], shell = True)
            Rouge_IDS.start() 
        elif input_var == 7:
            sys.exit(0)



class Rouge_IDS_Background(threading.Thread):
    def __init__(self, db , daemon):
        threading.Thread.__init__(self)
        self.daemon = daemon
        self.db = db

    def run(self):
        loop = True
        while loop:
            flag = 0
            for ap in self.db.all():
                    try:
                        print colored("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^", 'red')
                        print "$$$$$$$$$$$$$$$$$$$$$$$   Now Sannning -----> " , ap["ssid"]
                        print colored("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^", 'red')
                        s = scanning(intf="wlan4", count = 100, channel=ap["channel"], BSSID=ap["address"],SSID=ap["ssid"], accesspoint=ap, database=self.db)
                       
                       
                        if flag == 1:
                            for i in xrange(1, 3):
                                ch = random.randrange(1,11)
                                s.set_ch(ch)
                                s.ch_hop(ch, ap["ssid"])
                                s.sniffAP()
                                if i == 2:
                                    flag = 0
                         
                        if flag == 0:
                            s.set_ch(ap["channel"])
                            s.channel_change(ap["ssid"])
                            flag = 1                   
                        
                        s.sniffAP()
                        
                        if s.check_rm() == 1:
                            self.db.remove(where("ssid") == ap["ssid"])
                          
                    except KeyboardInterrupt, err:
                        print(traceback.format_exc())
                        print "interupted"                                         
            loop = False         





if __name__ == '__main__':
    from tinydb import TinyDB, where
    main()
    


    
class logging:
    def __init__(self):
        self.nothing = None

    def detected(pattern,msg):
            foo=open("DETECTIONS.LOG","a")
            logthis=str(datetime.datetime.today())+" | "+str(pattern)+" | "+str(msg)+"\n"
            foo.write(logthis)
            foo.close()



