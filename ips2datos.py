#!/usr/bin/python3
# -*- coding: UTF-8 -*-

"""
 Format the IP-GPS data to be used in a possible ANN
"""

fname = 'ips.dat'

data = open(fname,'r').read()

ips,lat,lon,year,month,day = [],[],[],[],[],[]
for l in data.splitlines():
   ll = l.split()
   ip,la,lo,y,m,d = ll
   ips.append(ip)
   lat.append(la)
   lon.append(lo)
   year.append(y)
   month.append(m)
   day.append(d)

s = '   '
g = open('datos.dat','w')
for i in range(len(ips)):
   ip,la,lo,y,m,d = ips[i],lat[i],lon[i],year[i],month[i],day[i]
   for x in ip.split('.'):
      g.write(x+s)
   g.write(y+s+m+s+d+s+la+s+lo+'\n')
g.close()
