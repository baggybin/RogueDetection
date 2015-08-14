#!/usr/bin/env python 
import subprocess 
import re 

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