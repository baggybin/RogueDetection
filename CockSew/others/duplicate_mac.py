# monitoir signal strenghts and frequency -- alter if change
# monitor mac addresses
# use some variety of white listing

"""
NETSTUMBLER: NetStumbler program sending out multiple probe requests
DEAUTHFLOOD: Deauthentication flood
CHANCHANGE: Channel changes that could indicate a rouge access point
BCASTDISCON: Disassociation attacks
PROBENOJOIN: Device that probes for open networks but never joins
DISASSOCTRAFFIC: Disassociation attack
NOPROBERESP: Possible DoS attack
BSSTIMESTAMP: Possible spoofed BSSID ---- change in timestamp sequence

ALERT Mon Mar 23 12:45:56 2009 Suspicious client 00:1A:73:02:6D:99 - probing
networks but never participating.

    Kismet supports the following alerts, where applicable the WVE (Wireless
    Vulnerability and Exploits, www.wve.org) ID is included:

        AIRJACKSSID         Fingerprint         Deprecated
            The original 802.11 hacking tools, Airjack, set the initial SSID
            to 'airjack' when starting up.  This alert is no longer relevant
            as the Airjack tools have long since been discontinued.

        APSPOOF             Fingerprint
            A list of valid MAC addresses for a SSID may be given via the
            'apspoof=' configuration file option.  If a beacon or probe
            response for that SSID is seen from a MAC address not in that
            list, this alert will be raised.  This can be used to detect
            conflicting access points, spoofed access points, or attacks
            such as Karma/Airbase which respond to all probe requests.

            The 'apspoof=' configuration option can specific exact SSID
            matches, regular expressions (if Kismet is compiled with PCRE
            support), and single, multiple, or masked MAC addresses:
                apspoof=Foo1:ssidregex="(?i:foobar)",validmacs=00:11:22:33:44:55

                apspoof=Foo2:ssid="Foobar",
                    validmacs="00:11:22:33:44:55,AA:BB:CCD:EE:FF"

            When multiple MAC addresses are specified, they should be
            enclosed in quotes (as above).

            For more information about forming PCRE-compatible regular
            expressions, see the PCRE docs (man pcrepattern).

        BSSTIMESTAMP        Trend/Stateful
            Invalid/Out-of-sequence BSS Timestamps can indicate AP spoofing.
            APs with fluctuating BSS timestamps could be suffering an "evil
            twin" spoofing attack, as many tools do not attempt to sync the
            BSS timestamp at all, and the fine-grained nature of the BSS
            timestamp field makes it difficult to spoof accurately.  Some
            APs may reset the BSS timestamp regularly, leading to a
            false-positive.

            References:
                WVE-2005-0019

        CHANCHANGE          Trend/Stateful
            A previously detected access point changing channels may
            indicate a spoofing attack.  By spoofing a legitimate AP on a
            different channel, an attacker can lure clients to the spoofed
            access point.  An AP changing channel during normal operation
            may indicate such an attack is in process, however centrally
            managed networks may automatically change AP channels to
            less-used areas of the spectrum.

             References:
                WVE-2005-0019

        CRYPTODROP          Trend/Stateful
            Spoofing an AP with less-secure encryption options may fool
            clients into connecting with compromised credentials.  The only
            situation in which an access point should reduce encryption
            security is when the AP is reconfigured.

        DEAUTHFLOOD         Trend/Stateful
        BCASTDISCON         Trend/Stateful
            By spoofing disassociate and deauthenticate packets an attacker
            may disconnect clients from a network, causing a
            denial-of-service which lasts only as long as the attacker is
            able to send the packets.

            References:
                WVE-2005-0019, WVE-2005-0045, WVE-2005-0046, WVE-2005-0061
                802.11ninja.net
                home.jwu.edu/jwright/papers/l2-wlan-ids.pdf

        DHCPCLIENTID        Fingerprint
            A client which sends a DHCP DISCOVER packet containing a
            Client-ID tag (Tag 61) which doesn't match the source MAC of the
            packet may be doing a DHCP denial-of-service to exhaust the DHCP
            pool.

        DHCPCONFLICT        Trend/Stateful
            Clients which receive a DHCP address and continue to use a
            different IP address may indicate a misconfigured or spoofed
            client.

        DISASSOCTRAFFIC     Trend/Stateful
            A client which is disassociated from a network should not
            immediately continue exchanging data.  This can indicate a
            spoofed client attempting to incorrectly inject data into a
            network, or can indicate a client being the victim of a
            denial-of-service attack.

        DISCONCODEINVALID   Fingerprint
        DEAUTHCODEINVALID   Fingerprint
            The 802.11 specification defines valid reason codes for
            disconnect and deauthenticate events.  Various client and access
            point drivers have been reported to improperly handle
            invalid/undefined reason codes.

        DHCPNAMECHANGE      Trend/Stateful
        DHCPOSCHANGE        Trend/Stateful
            The DHCP configuration protocol allows clients to optionally put
            the hostname and DHCP client vendor/operating system in the DHCP
            Discover packet.  These values should only change if the client
            has changed drastically (such as a dual-boot system).  Changing
            values can often indicate a client spoofing/MAC cloning attack.

        LONGSSID            Fingerprint
            The 802.11 specification allows a maximum of 32 bytes for the
            SSID.  Over-sized SSIDs are indicative of an attack attempting
            to exploit vulnerabilities in several drivers.

        LUCENTTEST          Fingerprint         Deprecated
            Old Lucent Orinoco cards in certain scanning test modes generate
            identifiable packets.

        MSFBCOMSSID         Fingerprint
            Some versions of the Windows Broadcom wireless drivers do not
            properly handle SSID fields longer than the 802.11
            specification, leading to system compromise and code execution.
            This vulnerability is exploited by the Metasploit framework.

            References:
                WVE-2006-0071

        MSFDLINKRATE        Fingerprint
            Some versions of the Windows D-Link wireless drivers do not
            properly handle extremely long 802.11 valid rate fields, leading
            to system compromise and code execution.  This vulnerability is
            exploited by the Metasploit framework.

            References:
                WVE-2006-0072

        MSFNETGEARBEACON    Fingerprint
            Some versions of the Windows netgear wireless drivers do not
            properly handle over-sized beacon frames, leading to system
            compromise and code execution.  This vulnerability is exploited
            by the Metasploit framework.

        NETSTUMBLER         Fingerprint         Deprecated
            Older versions of Netstumbler (3.22, 3.23, 3.30) generate, in
            certain conditions, specific packets.

        NULLPROBERESP       Fingerprint
            Probe-response packets with a SSID IE tag component of length 0
            can cause older cards (prism2, orinoco, airport-classic) to
            fail.

            References:
                WVE-2005-0019

        PROBENOJOIN         Trend/Stateful
            Active scanning tools such as Netstumbler constantly send
            network discovery probes but never join any of the networks
            which respond.  This alert can cause excessive false positives
            while channel hopping, and is disabled by default.

xample, WLAN users that send disassociation frames without being associated 
violate the IEEE-802.11 state machine access rule of associating prior to disassociation.



OUI

 sudo apt-get -y install python-netaddr
>>> from netaddr import *
>>> mac = EUI('bc:ae:c5:3b:fc:5e')
>>> print mac.oui.registration().org


"""

