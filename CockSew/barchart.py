import pandas as pd
import matplotlib.pyplot as plt

'''
Disregarded used different method to created bar charts

'''


s = pd.Series(
    [42.987, 42.812, 570.992, 313.512, 435.97,477.866],
    index = ["HW Average", "SW Average Other", "SW Airbase-NG VM", "SW Airbase-NG Android", "SW Airbase-NG Macbook","SW Airbase-NG Lenovo" ]
)
x = DataFrame({"Alpha": Series([42.987, 42.812, 570.992, 313.512, 435.97,477.866]), "Beta": Series(["HW Average", "SW Average Other", "SW Airbase-NG VM", "SW Airbase-NG Android", "SW Airbase-NG Macbook","SW Airbase-NG Lenovo" ])})

#Set descriptions:
plt.title("Total Delay Incident Caused by Carrier")
plt.ylabel('Delay Incident')
plt.xlabel('Carrier')

#Set tick colors:
ax = plt.gca()
ax.tick_params(axis='x', colors='blue')
ax.tick_params(axis='y', colors='red')

#Plot the data:
my_colors = 'rgbkymc'  #red, green, blue, black, etc.

pd.Series.plot(
    s, 
    kind='bar', 
    color=my_colors,
)
leg = plt.legend(loc=3, fancybox=True, shadow=True, fontsize = 'x-large')

plt.show()