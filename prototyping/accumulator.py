

class accumulator:
    def __init__(self, SSID, BSSID):
        self.SSID = ""
        self.BSSID = ""
        self.karma = []
        self.airbaseng = []
        self.seq = {}
        
    
    def addKarma(self, k):
        self.karma.append(k)
    
    def addAirbaseNG(self,a):
        self.airbaseng.append(a)
    
    def seqChange(self, ssid, val):
        self.seq[ssid] += val
        
    
    