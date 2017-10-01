#!/usr/bin/python3
# -*- coding: UTF-8 -*-

"""
 This functions aim to create a custom color map
"""

import matplotlib as mpl # in python

def mycmap(stops,Ns=[]):
   """
    This function returns a matplotlib colormap object.
    stops: color steps
    Ns: list of colors between steps.  len(Ns) = len(stops)-1
    if Ns is not provided. then Ns = [100 for _ in range(len(stops)-1)] is used
    ** alpha is allowed
    usage:
     col0 = np.array((149,177,104))
     col1 = np.array((225,216,222))
     col2 = np.array((167,102,113))
     stops = [col0/255,col1/255,col2/255]
     Ns = [4,11]
     cm = mycmap(stops,Ns=Ns)
   """
   if isinstance(Ns,int): Ns = [Ns for _ in range(len(stops)-1)]
   if isinstance(Ns,list):
      if len(Ns) == 0: Ns = [100 for _ in range(len(stops)-1)]
      else: pass
   if len(stops) != len(Ns)+1:
      print('Error making mycmap')
      return None
   cols = []
   for i in range(len(Ns)):
      N = Ns[i]
      col0 = stops[i]
      col1 = stops[i+1]
      for j in range(N):
         a = j/N
         c = (1-a)*col0 + a*col1
         #print(a,c)
         cols.append( tuple((1-a)*col0 + a*col1) )
   return mpl.colors.ListedColormap(cols)


if __name__ == '__main__':
   import numpy as np

   col0 = np.array((149,177,104))
   #  4 steps between these 2 colors
   col1 = np.array((225,216,222))
   # 11 steps between these 2 colors
   col2 = np.array((167,102,113))

   stops = [col0/255,col1/255,col2/255]
   Ns = [4,11]

   x = np.linspace(0,10,100)
   y = np.sin(x)

   import matplotlib.pyplot as plt
   cm = mycmap(stops,Ns=Ns)
   fig, ax = plt.subplots()
   C = ax.scatter(x,y,c=y,s=40,edgecolor='none',cmap=cm)
   fig.colorbar(C)
   plt.show()
