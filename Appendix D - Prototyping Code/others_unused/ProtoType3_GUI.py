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

# Method to return current system time
def t():
    return "[" + time.strftime("%H:%M:%S") + "] "


class mode_choice(wx.Frame):
    def __init__(self):
        """Constructor"""
        #set up a client instance
        #it will go though the protocol setup with the server
        self.m  = modes()

        #THE InterProcess Thread - The Main READING THREAD for the chat Client
        #Messages are passed through here
        #Checks for "Custom Commands" are also performed
        wx.Frame.__init__(self, None, -1, "Chat Room")
        panel = wx.Panel(self)
        sizer = wx.BoxSizer(wx.VERTICAL)

        # Create a messages display box
        self.text_send = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.TE_LEFT | wx.BORDER_NONE | wx.TE_READONLY)
        self.ctrl = wx.TextCtrl(self, style=wx.TE_PROCESS_ENTER, size=(300, 25))
        self.sendFile_Btn = wx.Button(self, 1, 'Button')

        #Also make a shallow copy of the AES Object
        #to stop of possible simultaneous access issues
        #and saves having to set it up again
        #newAes = copy.copy(self.client.a)
        #self.IPC = IPC_Read(self.client, self.text_send , self.ctrl, self, newAes, self.Shared_Mem_Dictionary)
        #create a new READING THREAD with a NEW SOSCKET to bind to
       	#self.newSocketRead = None#P2P_READ()
	'''
	loop = True
	while loop:
        input_var = int(input("1: Scan for Karma Access Points \n2: Scan a target to determine Airbase-NG \n3: Enter Whitelist AP \n4: Start Wireless IDS \n5: System Exit \n:>"))
        if input_var < 0 and input_var > 4:
            pass
        elif input_var == 1:
            result = m.KARMA_PROBE()
        elif input_var == 2:
            airbaseNG_Detection()
        elif input_var == 3:
            m.white_listing()
        elif input_var == 4:
            #Rouge_IDS()
            db = m.get_db()
            Rouge_IDS = Rouge_IDS_Background(db)
            Rouge_IDS.start() 
        elif input_var == 5:
            sys.exit(0)

	'''


        # add port entry box
        self.port = wx.StaticText(self, label="Enter a Port: ")
        self.portText = wx.TextCtrl(self, value="")

        self.rsa_radio = wx.RadioButton(self, label="RSA", style = wx.RB_GROUP)
        self.aes_radio = wx.RadioButton(self, label="AES")
        btn = wx.Button(self, label="Set File Transfer Mode")
        sizer.Add(self.text_send, 5, wx.EXPAND)
        sizer.Add(self.ctrl, 0, wx.EXPAND)
        sizer.Add(self.sendFile_Btn, 0, wx.EXPAND)
       # sizer.Add(self.choose_file, 0, wx.EXPAND)
        sizer.Add(self.rsa_radio, 0, wx.EXPAND)
        sizer.Add(self.aes_radio, 0, wx.EXPAND)
        sizer.Add(self.port, 0, wx.EXPAND)
        sizer.Add(self.portText, 0, wx.EXPAND)
        sizer.Add(btn, 0, wx.EXPAND)

        self.SetSizer(sizer)
        self.sendFile_Btn.Bind(wx.EVT_BUTTON, self.m.white_listing)
        btn.Bind(wx.EVT_BUTTON, self.onSet)

    # starts a file transmission from GUI
    def sendFile(self, event):
        """ Send File to Client """

    def onSet(self,event):
        #change transfer mode
        if self.rsa_radio.GetValue():
            self.fileTransferEncryption = 2
            dat ="<Entering RSA MODE>"
            self.standard_send_to(dat)
        if self.aes_radio.GetValue():
            dat ="<Entering AES MODE>"
            self.standard_send_to(dat)
            self.fileTransferEncryption = 1

	    
class MainPanel(wx.Panel):
    def __init__(self, parent):
        """Constructor"""
        wx.Panel.__init__(self, parent=parent)
        self.frame = parent
        m = modes()
        # Add a button to join the chatroom
        self.chat_room_button = wx.Button(self, -1, label="mode_choice")
        self.chat_room_button.Bind(wx.EVT_BUTTON, self.mode_choice)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self.chat_room_button, 0, wx.ALL|wx.CENTER, 5)
        self.SetSizer(sizer)

    def mode_choice(self, event):
        """ Opens the chat room frame """
        self.frame.Hide()
        m = mode_choice()
        m.Show()

class MainFrame(wx.Frame):
    def __init__(self):
        wx.Frame.__init__(self, None, -1, "Mode Choice")
        panel = MainPanel(self)


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
        choice = str(raw_input("Do you Wish to Scan for KARMA access points y/n"))
        if choice == "y" or choice == "Y":  
            k = karmaid()
            val = k.fakeSSID()
            print "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
            print "karma", val, "detected"
            print "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"     
        else:
            pass
    
    def airbaseNG_Detection(self):
        choice = str(raw_input("Do you Wish to Scan for Airbase-NG Access Points y/n \n"))
        if choice == "y" or choice == "Y":
            managed()
            ce = Cell.all("wlan4")
            s = []
            count = 0
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
            clock = ClockSkew(target["ssid"])
            clock.overlordfuntion()
            clock.rmse_function()
            time.sleep(1)
            f = open('rmse.txt','r')
            val3 = f.read()
            f.close()
    
    
            if Decimal(val3) > Decimal(299):     
               print "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
               print "Possible AIRBASE-NG Software Based Access Point"
               print "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"     
            else:
              print "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
              print "<<<<<<<<<<<<          Not AirBase-NG   <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
              print ""    
    
    def white_listing(self, event):
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
    
    def chann_change(channel):
        os.system("sudo ifconfig %s down" % "wlan4" )
        os.system("sudo iw dev "+ "wlan4" + " set type monitor")
        os.system("sudo ifconfig %s up" %  "wlan4")
        try:
            os.system("sudo iw dev %s set channel %d" % ("wlan4", channel))
            print "channel Change", channel
            print ""
        except Exception, err :
               print err
               
    def managed():
        os.system("sudo ifconfig %s down" % "wlan4" )
        os.system("sudo iw dev "+ "wlan4" + " set type managed")
        os.system("sudo ifconfig %s up" %  "wlan4")
        
    def purge_db():
        self.db.purge()
        return True
    
    
    def Rouge_IDS():
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
 
 
       
def main():
    m = modes()
    app = wx.App(False)
    frame = MainFrame()
    frame.Show()
    app.MainLoop()

    loop = True
    while loop:
        input_var = int(input("1: Scan for Karma Access Points \n2: Scan a target to determine Airbase-NG \n3: Enter Whitelist AP \n4: Start Wireless IDS \n5: System Exit \n:>"))
        if input_var < 0 and input_var > 4:
            pass
        elif input_var == 1:
            result = m.KARMA_PROBE()
        elif input_var == 2:
            airbaseNG_Detection()
        elif input_var == 3:
            m.white_listing()
        elif input_var == 4:
            #Rouge_IDS()
            db = m.get_db()
            Rouge_IDS = Rouge_IDS_Background(db)
            Rouge_IDS.start() 
        elif input_var == 5:
            sys.exit(0)



class Rouge_IDS_Background(threading.Thread):
    def __init__(self, db):
        threading.Thread.__init__(self)
        self.daemon = True
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
    
    
    #choice = str(raw_input("Do you Wish to Scan for KARMA access points y/n"))
    #if choice == "y" or choice == "Y":  
    #    k = karmaid()
    #    val = k.fakeSSID()
    #    print "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
    #    print "karma", val, "detected"
    #    print "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"     
    #else:
    #    pass
    #
    #choice = str(raw_input("Do you Wish to Scan for Airbase-NG Access Points y/n \n"))
    #if choice == "y" or choice == "Y":
    #    managed()
    #    ce = Cell.all("wlan4")
    #    s = []
    #    count = 0
    #    for c in ce:
    #        count += 1
    #        print ":"+ str(count), " ssid:", c.ssid
    #            #create dictionary with informnation on the accesss point
    #        SSIDS = {"no" : count ,"ssid": c.ssid, "channel":c.channel,"encrypted":c.encrypted, \
    #                    "frequency":c.frequency,"address":c.address, "signal":c.signal, "mode":c.mode}
    #            #append this dictionary to a list
    #        s.append(SSIDS)        
    #    
    #    input_var = int(input("Choose: "))
    #    print "-----------------------------------------"
    #    target = s[input_var - 1]
    #    
    #    chann_change(target["channel"])
    #    #targetSSID , ifaceno, switch, amount
    #    clock = ClockSkew(target["ssid"])
    #    clock.overlordfuntion()
    #    clock.rmse_function()
    #    time.sleep(1)
    #    f = open('rmse.txt','r')
    #    val3 = f.read()
    #    f.close()
    #
    #
    #    if Decimal(val3) > Decimal(299):     
    #       print "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
    #       print "Possible AIRBASE-NG Software Based Access Point"
    #       print "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"     
    #    else:
    #      print "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
    #      print "<<<<<<<<<<<<          Not AirBase-NG   <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
    #      print ""
    
    
    #interface = str(raw_input("Choose Interface for monitor: "))
    #os.system("sudo ifconfig %s down" %  interface)
    #os.system("sudo iwconfig "+  interface + " mode managed")
    #os.system("sudo ifconfig %s up" %  interface )
    #cell = Cell.all(interface)
    #db = TinyDB('db.json')
    ##db.purge()
    #Auth_AP = {}
    #S = []
    ##have a counter for user choice input
    #count = 0
    #for c in cell:
    #    count += 1
    #    print ":"+ str(count), " ssid:", c.ssid
    #        #create dictionary with informnation on the accesss point
    #    SSIDS = {"no" : count ,"ssid": c.ssid, "channel":c.channel,"encrypted":c.encrypted, \
    #                "frequency":c.frequency,"address":c.address, "signal":c.signal, "mode":c.mode}
    #        #append this dictionary to a list
    #    S.append(SSIDS)
    ### get choice from the user
    #input_var = int(input("Choose: "))
    #print "---------------------------------------------"
    #ap = S[input_var - 1]
    #print ap["ssid"]
    #print ap["address"]
    #print ap["encrypted"]
    #print ap["channel"]
    #print "---------------------------------------------"
    #
    #loop = True
    #while loop:
    #    try:
    #        input_var = int(input("1: Store Valid AP \n2: Disregard and Continue\n:"))     
    #        if input_var > 0 and input_var <= 2:
    #            loop = False
    #    except ValueError:
    #        pass
    #
    #if input_var == 1:
    #    #db.purge()
    #    #db.insert(S[input_var - 1])
    #    #if db.search((where('ssid') == ap["ssid"]) & (where('address') == str(ap["address"]))) == []:
    #    #    db.insert(ap)
    #    #else:
    #    #    print "This is already Stored in the database"
    #    if db.search((where('ssid') == ap["ssid"]) & (where('address') == str(ap["address"]))) == []:
    #        db.insert(ap)
    #    else:
    #        print "already Stored in the database"
    #    
    #    '''
    #    print all database
    #    '''
    #    print db.all()
        
    #ch = channel_hop()
    #_thread = threading.Thread(target=ch.run(debug = True, iface = "wlan4"))
    #_thread.start()
    
    

    #loop = True
    #while loop:
    #    flag = 0
    #    for ap in db.all():
    #            try:
    #                print colored("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^", 'red')
    #                print "$$$$$$$$$$$$$$$$$$$$$$$   Now Sannning -----> " , ap["ssid"]
    #                print colored("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^", 'red')
    #                s = scanning(intf="wlan4", count = 100, channel=ap["channel"], BSSID=ap["address"],SSID=ap["ssid"], accesspoint=ap, database=db)
    #               
    #               
    #                if flag == 1:
    #                    for i in xrange(1, 3):
    #                        ch = random.randrange(1,11)
    #                        s.set_ch(ch)
    #                        s.ch_hop(ch, ap["ssid"])
    #                        s.sniffAP()
    #                        if i == 2:
    #                            flag = 0
    #                 
    #                if flag == 0:
    #                    s.set_ch(ap["channel"])
    #                    s.channel_change(ap["ssid"])
    #                    flag = 1                   
    #                
    #                s.sniffAP()
    #                
    #                if s.check_rm() == 1:
    #                    db.remove(where("ssid") == ap["ssid"])
    #                  
    #            except KeyboardInterrupt, err:
    #                print(traceback.format_exc())
    #                print "interupted"                                         
    #    loop = False                      



