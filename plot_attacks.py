#!/usr/bin/python3
# -*- coding: UTF-8 -*-

import matplotlib
matplotlib.use('Agg')
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.mlab import griddata
import os
here = os.path.dirname(os.path.realpath(__file__))  # script folder
HOME = os.getenv('HOME')



M = np.load(here+'/attacks.npy')
LAT = M[:,0]
LON = M[:,1]
NUM = M[:,2]
WHEN = np.array([(1,0,0,a) for a in M[:,3]])
#LAT,LON,NUM,WHEN = np.loadtxt('attacks.csv',delimiter=',',unpack=True)
#WHEN = [(1,0,0,a) for a in WHEN]

fname = here+'/mundo.npy'
M = np.load(fname)
Y = M[:,0]
X = M[:,1]
Z = M[:,2]
## define grid.
#xi = np.reshape(X,(360,180))
#yi = np.reshape(Y,(360,180))
#zi = np.reshape(Z,(360,180))
print('gridding...')
###from matplotlib.mlab import griddata
xi = np.linspace(min(X),max(X),360)
yi = np.linspace(min(Y),max(Y),180)
zi = griddata(X,Y,Z,xi,yi)
print('...done')

#### Plot ####
#fig, ax = plt.subplots(figsize=cm2inch(40,20),frameon=False)
###########################
def cm2inch(*tupl,inch=2.54):
   if isinstance(tupl[0], tuple): return tuple(i/inch for i in tupl[0])
   else: return tuple(i/inch for i in tupl)
###########################
fig = plt.figure(figsize=cm2inch(40,20),frameon=False)
ax = fig.add_axes([0, 0, 1, 1])
ax.axis('off')

## My personalized colormap
col0 = np.array((15,36,99))     # dark blue    | Sea
col1 = np.array((79,106,166))   # light blue___|_____
col2 = np.array((149,177,104))  # light green  |
col3 = np.array((225,216,222))  # white-ish    | Land
col4 = np.array((167,102,113))  # red-ish      |

stops = [col0/255,col1/255,col2/255,col3/255,col4/255]
Ns = [100,2,15,85]
from mycolor import mycmap
cm = mycmap(stops,Ns=Ns)
l = 9000
## Surface image
ax.contourf(xi, yi, zi,zorder=0,cmap=cm,vmin=-l,vmax=l)
ax.scatter(LON,LAT,s=20*NUM,c=WHEN,edgecolors='none',zorder=10)

## Plot settings
ax.set_xlim(min(X),max(X))
ax.set_ylim(min(Y),max(Y))
ax.set_aspect('equal')

fig.patch.set_visible(False)
ax.axis('off')
with open(HOME+'/attacks.png', 'w') as outfile:
    fig.canvas.print_png(outfile)
plt.show()
