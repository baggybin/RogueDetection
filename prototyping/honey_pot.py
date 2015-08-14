import os
import subprocess
from lease_check import *
import nmap
nm = nmap.PortScanner()


'''
Starts a WIFIhoney Pot using
hostAPD
assigns DHCP addressing with dhcpd
chechk active leases and does
Nmap scan

nmap scan does not funtion well currently 
'''

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
        
        for lease in report_dataset:
                #result = nm.scan(lease['ip_address'], '1-1024', '-n', '-Pn')
                #print nm.scaninfo()
                print "rrrr"
                result = nm.scan(hosts=lease['ip_address'], arguments='-n -sP -PE -PA21,23,80,3389')
                print result
                
                for host in nm.all_hosts():
                    print('----------------------------------------------------')
                    print('Host : %s (%s)' % (host, nm[host].hostname()))
                    print('State : %s' % nm[host].state())
                    for proto in nm[host].all_protocols():
                        print('----------')
                        print('Protocol : %s' % proto)
                        lport = nm[host][proto].keys()
                        lport.sort()
                        for port in lport:
                            print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
                
                #print "ssss"
                print(nm.csv())
                #nm.scan(hosts=lease['ip_address'], arguments='-n -Pn -p1-1024')
                #print(nm.csv())
                
                print('----------------------------------------------------')
                # Asynchronous usage of PortScannerAsync
                
                
                nma = nmap.PortScannerAsync()
                
                def callback_result(host, scan_result):
                    print('------------------')
                    print(host, scan_result)
                
                nma.scan(hosts=lease['ip_address'], arguments='-sP', callback=callback_result)
                
                while nma.still_scanning():
                    print("Waiting ...")
                    nma.wait(2)   # you can do whatever you want but I choose to wait after the end of the scan
                
                #if (os.getuid() == 0):
                #    print('----------------------------------------------------')
                #    # Os detection (need root privileges)
                #    ip = lease['ip_address']
                #    nm.scan(ip ,arguments="-O")
                #    if 'osclass' in nm[ip]:
                #        for osclass in nm[ip]['osclass']:
                #            print('OsClass.type : {0}'.format(osclass['type']))
                #            print('OsClass.vendor : {0}'.format(osclass['vendor']))
                #            print('OsClass.osfamily : {0}'.format(osclass['osfamily']))
                #            print('OsClass.osgen : {0}'.format(osclass['osgen']))
                #            print('OsClass.accuracy : {0}'.format(osclass['accuracy']))
                #            print('')
                #
                #    if 'osmatch' in nm[lease['ip_address']]:
                #        for osmatch in nm[lease['ip_address']]['osmatch']:
                #            print('OsMatch.name : {0}'.format(osclass['name']))
                #            print('OsMatch.accuracy : {0}'.format(osclass['accuracy']))
                #            print('OsMatch.line : {0}'.format(osclass['line']))
                #            print('')
                #
                #    if 'fingerprint' in nm[lease['ip_address']]:
                #        print('Fingerprint : {0}'.format(nm[lease['ip_address']]['fingerprint']))
                
                
                    # Vendor list for MAC address
                    nm.scan(lease['ip_address'], arguments='-O')
                    for h in nm.all_hosts():
                        if 'mac' in nm[h]['addresses']:
                            print(nm[h]['addresses'], nm[h]['vendor'])
                        #try:
                        #    print nm[h]['addresses']['osclass']
                        #except:
                        #    print"os err"
                   
#if __name__ == '__main__':
#    h = honey()
#    h.leases()
#        
        