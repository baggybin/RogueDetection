

"""

OUI

 sudo apt-get -y install python-netaddr
>>> from netaddr import *
>>> mac = EUI('bc:ae:c5:3b:fc:5e')
>>> print mac.oui.registration().org


"""

