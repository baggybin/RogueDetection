from json import dumps, loads, JSONEncoder, JSONDecoder
import pickle

'''
Was used to store all results from all tests that were perfromed in 
Clock skew measurement 

'''

'''
Class to encode Python Objects and Types
using the Json Encoder Module
'''
class PythonObjectEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (list, dict, str, unicode, int, float, bool, type(None))):
            return JSONEncoder.default(self, obj)
        return {'_python_object': pickle.dumps(obj)}

'''
pickle an Object - Serialization
'''
def as_python_object(dct):
    if '_python_object' in dct:
        return pickle.loads(str(dct['_python_object']))
    return dct

f = open('output.txt', 'r')

j = f.read()
d = loads(j, object_hook=as_python_object)

print d["bssid"]

