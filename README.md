# RougeDetection
Rouge Access Point Detection and WIDS

The project involved an in-depth research into current methodologies in use for rouge access point detection. The chosen approach taken involved aspects of many of the different methodologies that were investigated, with a particular directive in developing a wireless side detection system for a client station that was not reliant on information derived from a wired backbone network. The type of rouge access points of particular interest in this area were phishing rouges such as KARMA based attacks and Evil Twins. 

The majority of rouge access points used by attackers are generated in software and not on a dedicated device, for this reason a method of differentiating between software and hardware based access points was investigated. To achieve this, clock skews, which are tiny drifts in computer clock timings were used as a potential fingerprint as it is assumed that the virtualisation used in a software based access point would generate larger clock drifts than their hardware brethren. During the investigation it was discovered that the only software access point detectable with this methodology was one generated with Airbase-NG, as other software access points such as the HostAPD daemon pass the timing functionality to the low level driver of the wireless interface reproducing the timing of hardware.

KARMA attacks automatically reply to probes for networks and attempt for transparent associations of it victims. It was found that KARMA based rouges were easily detectable by sending individual requests for randomly generated networks and checking for a connection to this fake network.

During the projects development it was decided that wireless IDS based functionality be added to give a more comprehensive toolset for rouge detection. Changing the projects focus from a client side only detection system to something a little broader in its approach.


