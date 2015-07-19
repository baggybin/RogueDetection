from wifi import Cell, Scheme
cell = Cell.all('wlan4')

Auth_AP = {}
S = []
count = 0 
for c in cell:
	count += 1
	print ":"+ str(count), " ssid:", c.ssid
	SSIDS = {"no" : count ,"ssid": c.ssid, "channel":c.channel,"encrypted":c.encrypted, "frequency":c.frequency,	"address":c.address, "signal":c.signal,  "mode":c.mode}
	S.append(SSIDS)
	#"bitrates":c.bitrates,


input_var = int(input("Choose: "))
print "-----------------------------------------"

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
