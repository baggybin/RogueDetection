#!/usr/bin/env python
import sys
import random

import PyLorcon2

from impacket import dot11
from impacket.dot11 import Dot11
from impacket.dot11 import Dot11Types
from impacket.dot11 import Dot11ManagementFrame
from impacket.dot11 import Dot11ManagementProbeRequest

def getProbeRequest(src, ssid):
    "Return 802.11 Probe Request Frame."

    # Frame Control
    frameCtrl = Dot11(FCS_at_end = False)
    frameCtrl.set_version(0)
    frameCtrl.set_type_n_subtype(
    Dot11Types.DOT11_TYPE_MANAGEMENT_SUBTYPE_PROBE_REQUEST)
    # Frame Control Flags
    frameCtrl.set_fromDS(0)
    frameCtrl.set_toDS(0)
    frameCtrl.set_moreFrag(0)
    frameCtrl.set_retry(0)
    frameCtrl.set_powerManagement(0)
    frameCtrl.set_moreData(0)
    frameCtrl.set_protectedFrame(0)
    frameCtrl.set_order(0)

    # Management Frame
    sequence = random.randint(0, 4096)
    broadcast = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    mngtFrame = Dot11ManagementFrame()
    mngtFrame.set_duration(0)
    mngtFrame.set_destination_address(broadcast)
    mngtFrame.set_source_address(src)
    mngtFrame.set_bssid(broadcast)
    mngtFrame.set_fragment_number(0)
    mngtFrame.set_sequence_number(sequence)

    # Probe Request Frame
    probeRequestFrame = Dot11ManagementProbeRequest()
    probeRequestFrame.set_ssid(ssid)
    rates = [0x82, 0x84, 0x8b, 0x96, 0x0c, 0x18, 0x30, 0x48]
    probeRequestFrame.set_supported_rates(rates)

    idType = dot11.DOT11_MANAGEMENT_ELEMENTS.EXT_SUPPORTED_RATES
    value = "\x12\x24\x60\x6c"
    probeRequestFrame._set_element(idType, value)

    mngtFrame.contains(probeRequestFrame)
    frameCtrl.contains(mngtFrame)

    return frameCtrl.get_packet()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print "Usage"
        print "  %s   " % sys.argv[0]
        sys.exit()

    iface = sys.argv[1]
    essid = sys.argv[2]

    context = PyLorcon2.Context(iface)
    context.open_injmon()
    moniface = context.get_capiface()

    src = [0x00, 0x00, 0x00, 0x11, 0x22, 0x33]
    probeRequest = getProbeRequest(src, essid)

    if essid == "":
        essid = "broadcast"

    print "Using interface %s" % iface
    print "Injecting Probe Requests for '%s'." % essid

    context.send_bytes(probeRequest)
