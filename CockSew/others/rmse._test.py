from pylab import *
import math
from decimal import *

time = [0,1,2,3,4,5,6,7,8,9,10]
position = [0.11,0.19,0.3,0.41,0.48,0.58,0.64,0.69,0.83,0.92,1.04]

#Linear Fitting
'''
This calls the polyfit function (that is in the pylab module).
Polyfit takes two variables and a degree. In this case the degree is 1 for a linear function.
The results goes to the two variables m (for the slope) and b for the y-intercept of the equation y = mx + b.
'''
(m,b) = polyfit(time,position,1)
print m, b

'''
This just evaluates the polynomial with the coefficients [m,b] and value x.
So, for every x data point I have, this calculates a y value from the fitting function.
Now I have a new set of values yp
'''
yp = polyval([m,b],time)
print yp

#model predicitons for each time
model = []
for i in range(len(time)):
    val = Decimal(Decimal(time[i]) * Decimal(m)  + Decimal(b))
    model.append(val)
    print val

"residuals --- the difference between model prediction and the line"
print "residuals"
residuals = []
residualsSquared = []
for i in range(len(time)):
    res = Decimal(Decimal(position[i]) - model[i])
    residuals.append(res)
    print res
    print "squared", res * res
    residualsSquared.append(res * res)

"root mean square error calcuation"
mean = Decimal(sum(residualsSquared)/len(residualsSquared))
rmse = Decimal(math.sqrt(mean))

print ""
print "RMSE", rmse

#plot(time, yp)
#scatter(time, position)
#xlabel('time')
#ylabel('position')
#show()
