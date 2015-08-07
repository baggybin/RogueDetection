import os
import subprocess
from lease_check import *

class honey:
    def __init__(self):   
        pass
    
    def start_honey(self):
        #subprocess.call("airmon-ng check kill", stdin=None, stdout=None, stderr=None, shell=True)
        subprocess.call(['airmon-ng','check','kill'],stdin=None, stdout=None, stderr=None, shell=False )
        start = subprocess.call(['python' ,'hostapd.py/hostapd.py' ,'start'], stdin=None, stdout=None, stderr=None, shell=False)
        return start
    
    
    def stop_honey(self):
        stop = subprocess.call(['python' ,'hostapd.py/hostapd.py' ,'stop'], stdin=None, stdout=None, stderr=None, shell=False)
        return stop
    
    
    def leases(self):
        l = lease_check()
        myfile = open('/var/lib/dhcp/dhcpd.leases', 'r')
        leases = l.parse_leases_file(myfile)
        myfile.close()
        now = l.timestamp_now()
        report_dataset = l.select_active_leases(leases, now)
        print('+------------------------------------------------------------------------------')
        print('| DHCPD ACTIVE LEASES REPORT')
        print('+-----------------+-------------------+----------------------+-----------------')
        print('| IP Address      | MAC Address       | Expires (days,H:M:S) | Client Hostname ')
        print('+-----------------+-------------------+----------------------+-----------------')
        
        for lease in report_dataset:
                print('| ' + format(lease['ip_address'], '<15') + ' | ' + \
                        format(lease['hardware'], '<17') + ' | ' + \
                        format(str((lease['ends'] - now) if lease['ends'] != 'never' else 'never'), '>20') + ' | ' + \
                        lease['client-hostname'])
        print('+-----------------+-------------------+----------------------+-----------------')
        print('| Total Active Leases: ' + str(len(report_dataset)))