import sys, os 
from multiprocessing import Process
from scapy.all import *
import binascii


interface = "mon0"

def ch_hopp():
    while True:
        try:
            channel = random.randrange(1,13)
            # os.system("sudo iw dev %s set channel %d" % (interface, channel))
            # os.system("sudo iwlist mon0 scan essid Dildo | grep dildo")
            time.sleep(1)
        except KeyboardInterrupt:
            break



p = Process(target = ch_hopp)
p.start()
