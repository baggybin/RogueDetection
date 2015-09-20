#! /bin/bash
from scapy.all import *
import json

for i in {1}
do   
counter=0
fakeSSID=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)
echo "RaNDOIM Generateed SSID "
echo $fakeSSID

sudo service network-manager stop
sudo ifconfig wlan4 down
sudo iwconfig wlan4 essid $fakeSSID
sudo ifconfig wlan4 up
echo "Currently Assossoated AP"
sudo iwconfig wlan4 | awk 'NR==1{print $4}'
#NUM_PROCS=$(sudo iwconfig wlan4 | awk 'NR==1{print $4}')
AP=$(iwconfig wlan4 | grep 'ESSID:' | awk '{print $4}' | sed 's/ESSID://g' | sed 's/"//g')
#Ass=$(sudo  iwconfig wlan4 | grep "Access Point:" | awk '{print $6}' | cut -c 1-17)


BSSID=$(iwconfig wlan4 | grep "Access Point:" | awk '{print $6}')
echo "BSSID"
echo $BSSID

if [ "$fakeSSID" == "$AP" ];then
    echo "matchh"
    echo $Ass
fi
done


ifconfig wlan4 down
iwconfig wlan4 mode managed
ifconfig wlan4 up


echo "mac addreesss" 
echo $Ass

case $Ass
in 
  [0-9a-f][0-9a-f]:[0-9a-z][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f])
    echo "Valid MAC"
    $counter=counter+1
  ;;
  *) echo "Try again"
  ;;
esac





