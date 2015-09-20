import os, sys
if len(sys.argv) != 3:
    print "Usage %s monitor_interface" % sys.argv[0]
    sys.exit(1)

channel = int(sys.argv[1])
iface = sys.argv[2]

os.system("ifconfig %s down" % iface)
os.system("sudo iw dev " + iface + " set type monitor")
os.system("ifconfig "+iface+" up")
os.system("iw dev %s set channel %d" % (iface, channel))