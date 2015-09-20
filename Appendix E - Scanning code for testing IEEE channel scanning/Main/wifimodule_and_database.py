#import the wifi modules
from wifi import Cell, Scheme
#scan with the wireless interface
cell = Cell.all('wlan4')

Auth_AP = {}
S = []
#have a counter for user choice input
count = 0
'''
for each access point stored
add to counter
print out the ssid for choice
and store in in LIST
'''
for c in cell:
	count += 1
	print ":"+ str(count), " ssid:", c.ssid
	#create dictionary with informnation on the accesss point
	SSIDS = {"no" : count ,"ssid": c.ssid, "channel":c.channel,"encrypted":c.encrypted, \
		 "frequency":c.frequency,"address":c.address, "signal":c.signal, "mode":c.mode}
	#append this dictionary to a list
	S.append(SSIDS)

## get choice from the user
input_var = int(input("Choose: "))
print "-----------------------------------------"
'''
at the moment just print out information abount the chosen access point
'''
ap = S[input_var - 1]
print ap["ssid"]
# store aurtorised in a dictionary
Auth_AP[ap["ssid"]] = ap
print "__________________"
print Auth_AP







# Auth_AP[ap[ssid]] = ap[input_var]
# db = dataset.connect('sqlite:///auth_ap.db', row_type=stuf)
# table = db['auth_ap']
# table.insert(SSIDS)


# print  "-----------------------------------------------"
# #print(db.tables)
# #print(db['auth_ap'].columns)

# for u in db['auth_ap']:
#    print(S[input_var].get['ssid'])
#    print (u['address'])
