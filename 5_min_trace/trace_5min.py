from json import dumps, loads, JSONEncoder, JSONDecoder
import pickle
import matplotlib.pyplot as plt

class PythonObjectEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (list, dict, str, unicode, int, float, bool, type(None))):
            return JSONEncoder.default(self, obj)
        return {'_python_object': pickle.dumps(obj)}

def as_python_object(dct):
    if '_python_object' in dct:
        return pickle.loads(str(dct['_python_object']))
    return dct

f = open('nexus_nethunter.txt', 'r')
j = f.read()
nexus_nethunter = loads(j, object_hook=as_python_object)

f = open('nexus_thether.txt', 'r')
j = f.read()
nexus_thether = loads(j, object_hook=as_python_object)

f = open('kalivm_airbaseng.txt', 'r')
j = f.read()
kalivm_airbase_ng = loads(j, object_hook=as_python_object)

f = open('nexus_airbase_ng.txt', 'r')
j = f.read()
nexus_airbase_ng = loads(j, object_hook=as_python_object)

f = open('zoom2.txt', 'r')
j = f.read()
zoom2 = loads(j, object_hook=as_python_object)

f = open('second_airbng_nexus.txt', 'r')
j = f.read()
second_airbng_nexus = loads(j, object_hook=as_python_object)

f = open('tplink.txt', 'r')
j = f.read()
tplink = loads(j, object_hook=as_python_object)

f = open('zyxel.txt', 'r')
j = f.read()
zyxel = loads(j, object_hook=as_python_object)

f = open('lenovo_airbase_ng.txt', 'r')
j = f.read()
lenovo_airbase_ng = loads(j, object_hook=as_python_object)

f = open('pineapple_hostapd.txt', 'r')
j = f.read()
pineapple_hostapd= loads(j, object_hook=as_python_object)

for key, value in zoom2.iteritems() :
    print key
import numpy as np
import pylab

time = zoom2["x"]

linestying=""

plt.grid(True)
pylab.xlim(xmin=0)
pylab.xlim(xmax=int(max(time)))
linew = 0.5
plt.plot(time, zoom2["y"], label="HW - Zoom 4403", color="grey", linestyle='-',linewidth=1, antialiased=True, alpha=1.00)
#plt.plot(nexus_airbase_ng["x"], nexus_airbase_ng["y"], label="SW - Nexus AirBase-NG 1", color="blue", linestyle='-',linewidth=1)
plt.plot(tplink["x"], tplink["y"], label="HW - TPlink 0000", color="red", linestyle='-',linewidth=1, antialiased=True)
plt.plot(zyxel["x"], zyxel["y"], label="HW - zyxel", color="green", linestyle='-',linewidth=1, antialiased=True)
#plt.plot(lenovo_airbase_ng["x"], lenovo_airbase_ng["y"], label="SW - Lenovo G570 AirBase-NG", color="pink", linestyle='-',linewidth=linew, antialiased=True)
plt.plot(nexus_thether["x"], nexus_thether["y"], label="SW - Nexus Android Thether", color="yellow", linestyle='-',linewidth=1, antialiased=True)
plt.plot(kalivm_airbase_ng["x"], kalivm_airbase_ng["y"], label="SW - Kali VM AirBase-NG", color="blue", linestyle='-',linewidth=linew, antialiased=True)
plt.plot(nexus_nethunter["x"], nexus_nethunter["y"], label="SW - Nexus HostAPD", color="orange", linestyle='-',linewidth=1, antialiased=True)
plt.plot(second_airbng_nexus["x"], second_airbng_nexus["y"], label="SW - Nexus AirBase-NG 2", color="purple", linestyle='-',linewidth=linew, antialiased=True)
plt.plot(pineapple_hostapd["x"], pineapple_hostapd["y"], label="SW - PineApple HostAPD", color="black", linestyle='-',linewidth=1, antialiased=True)
plt.xticks(np.arange(min(time), int(max(time)) + 1, 20.0))	


# size = 5
# plt.scatter(time, zoom2["y"], label="HW - Zoom 4403", color="grey", marker="1", antialiased=True, s=size)
# #plt.plot(nexus_airbase_ng["x"], nexus_airbase_ng["y"], label="SW - Nexus AirBase-NG 1", color="blue", linestyle='-',linewidth=1)
# plt.scatter(tplink["x"], tplink["y"], label="HW - TPlink 0000", color="red", marker="1",antialiased=True, s=size)
# plt.scatter(zyxel["x"], zyxel["y"], label="HW - zyxel", color="green",marker="1", antialiased=True, s=size)
# plt.scatter(lenovo_airbase_ng["x"], lenovo_airbase_ng["y"], label="SW - Lenovo G570 AirBase-NG", color="black",marker="1", antialiased=True, s=size)
# plt.scatter(nexus_thether["x"], nexus_thether["y"], label="SW - Nexus Android Thether", color="yellow", marker="1", antialiased=True, s=size)
# plt.scatter(kalivm_airbase_ng["x"], kalivm_airbase_ng["y"], label="SW - Kali VM AirBase-NG", color="blue", marker="1", antialiased=True, s=size)
# plt.scatter(nexus_nethunter["x"], nexus_nethunter["y"], label="SW - Nexus HostAPD", color="orange",marker="1",  antialiased=True, s=size)
# plt.scatter(second_airbng_nexus["x"], second_airbng_nexus["y"], label="SW - Nexus AirBase-NG 2", color="purple", marker="1", antialiased=True, s=size)
# plt.scatter(pineapple_hostapd["x"], pineapple_hostapd["y"], label="SW - PineApple HostAPD", color="black", marker="1", antialiased=True, s=size)
# plt.xticks(np.arange(min(time), int(max(time)) + 1, 10.0))	



plt.xlabel("Seconds")
plt.ylabel('Microsecond offset')
from matplotlib import legend_handler


leg = plt.legend(loc=3, fancybox=True, shadow=True)

for legobj in leg.legendHandles:
    legobj.set_linewidth(4.0)

plt.show() 