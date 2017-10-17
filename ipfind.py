#!/usr/bin/python3
# -*- coding: UTF-8 -*-

import numpy as np
from math import sin, cos, atan2, sqrt, radians
import sys

def points2distance(start, end, R0=6371):
   """
     Calculate distance (in kilometers) between two points given as
     (long, latt) pairs based on Haversine formula:
     http://en.wikipedia.org/wiki/Haversine_formula
     R0 = 6371km is the radious of the earth
   """
   ## Degrees to Radians
   start_long = radians(start[0])  # Start point
   start_latt = radians(start[1])  #
   end_long = radians(end[0])  # End point
   end_latt = radians(end[1])  #
   d_long = end_long - start_long
   d_latt = end_latt - start_latt
   a = sin(d_latt/2)**2 + cos(start_latt) * cos(end_latt) * sin(d_long/2)**2
   c = 2 * atan2(sqrt(a), sqrt(1-a))
   return R0 * c

try: p = tuple(map(float,sys.argv[1].split(',')))
except IndexError: p = (52.094021,5.118713)
p = tuple(reversed(p))

try: fname = sys.argv[2]
except IndexError: fname = 'ips.dat'

try: N = sys.argv[3]
except IndexError: N = 5



lat,lon = np.loadtxt(fname,usecols=(1,2),unpack=True)
ips = np.loadtxt(fname,usecols=(0,),unpack=True,dtype=bytes)
ips = np.array([str(x,'utf-8') for x in ips])



dist = [points2distance(p,(lon[i],lat[i])) for i in range(len(lat))]
ind = np.argsort(dist)
print('Closest IPs to (%s,%s):'%(p[1],p[0]))
for i in ind[0:N]:
   print('  -',ips[i].ljust(15),'  (%.2f km)'%(dist[i]))
