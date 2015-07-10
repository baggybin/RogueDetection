#! /bin/bash

# for i in {1}
# do   

# counter=0
# fakeSSID=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)
# echo "RaNDOIM Generateed SSID "
# echo $fakeSSID
# sudo ifconfig wlan4 down
# sudo iwconfig wlan4 essid $fakeSSID
# sudo ifconfig wlan4 up
# echo "Currently Assossoated AP"
# sudo iwconfig wlan4 | awk 'NR==1{print $4}'
# #NUM_PROCS=$(sudo iwconfig wlan4 | awk 'NR==1{print $4}')
# AP=$(iwconfig wlan4 | grep 'ESSID:' | awk '{print $4}' | sed 's/ESSID://g' | sed 's/"//g')

# sudo iwconfig wlan4
# if [ "$fakeSSID" == "$AP" ];then
#     echo "matchh"
# fi
# done









