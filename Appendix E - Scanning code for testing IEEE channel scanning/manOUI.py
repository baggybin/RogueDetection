#! /bin/python


'''
Doesnt Correctly ID OUI
'''

from netaddr import *


mac = EUI('00-50-C2-00-0F-01') 
print  mac.is_iab()
iab = mac.iab
iab
print iab.registration()


mac = EUI('11-11-11-11-11-01')
print  mac.is_iab()
iab = mac.iab
iab
if mac.is_iab():
 print  iab.registration()

