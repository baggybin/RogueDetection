from wifi import Cell, Scheme
cell = Cell.all('wlan4')


for c in cell:
	print c.ssid
	print c.channel	
	print c.encrypted
	print c.frequency	
	print c.bitrates
	print c.address
	print c.signal
	print c.mode

