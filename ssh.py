#!/usr/bin/python3
# -*- coding: UTF-8 -*-

"""
  This code will extract and simplify the log file for ssh failed logins and
  port scans...
"""

import os
here = os.path.dirname(os.path.realpath(__file__))  # script folder
HOME = os.getenv('HOME')
USER = os.getenv('USER')

## personal system-wide log tools and decorators, which can be found here:
# https://github.com/B4dWo1f/bin/blob/master/log_help.py
import log_help
import logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)s:%(levelname)s - %(message)s',
                    datefmt='%Y/%m/%d-%H:%M:%S',
                    filename='SSHlog.log', filemode='w')
LG = logging.getLogger('main')
log_help.screen_handler(LG)

# dependence on my geoip library, which can be found here:
# https://github.com/B4dWo1f/bin/blob/master/geoip.py
import geoip
import parser as func
import datetime as dt
import numpy as np
import sys


## Standard input to select file and hostname, mainly for debugging
# TODO: maybe argparse this
try: log_file = sys.argv[1]
except IndexError: log_file = '/var/log/auth.log'

try: hostname = sys.argv[2]
except IndexError: hostname = os.uname()[1]

ips_file = here + '/ips.dat'  # Local database of IP-GPS
ndays = int(open('Ndays').read())  # Number of days to update IP-GPS data

## Read file and  Analyze the sshd entries
sshd_logins = os.popen('grep " sshd\[" %s'%(log_file)).read().splitlines()

## Classify the entries to study
accepted_logins = []     #
failed_logins = []       #   Different levels of
alert_logins = []        # info depending on the auth log
input_user = []          #
port_scans = []          #
for l in sshd_logins:
   if 'Accepted' in l: accepted_logins.append(l)
   elif ' Failed password' in l: failed_logins.append(l)
   #elif ' Received disconnect' in l: failed_logins.append(l)
   elif ' pam_unix' in l: pass       # TODO In principle these are not attacks
   elif ' Disconnecting:' in l: pass # or no information here
   #elif ' PAM ' in l: failed_logins.append(l)  #TODO check info
   elif ' input_userauth_request: ' in l: input_user.append(l)  #TODO study
   elif ' Invalid user ' in l: failed_logins.append(l)
   elif ' Connection closed by ' in l: failed_logins.append(l) # Not complete
   elif ' reverse mapping checking getaddrinfo ' in l: alert_logins.append(l)
   elif ' fatal: ' in l: pass  #TODO study
   elif ' Did not receive identification string from ' in l: port_scans.append(l)
   else: pass


## Extract info from each attempt
logins = failed_logins + alert_logins + port_scans
LG.info('Evaluating %s attempts'%(len(logins)))
attempts = []
for l in logins: # TODO Split contributions
   resp = func.parse_attempt(l) #,hostname=hostname)
   if resp != None: attempts.append(resp)


## Extract all the IPs
IPs = [T.ip for T in attempts]
dates = [T.date for T in attempts]
ports = [T.port for T in attempts]
dif_IPs = list(sorted(set(IPs),key=lambda x: float(x.split('.')[0])))

## To array
IPs = np.asarray(IPs)
dates = np.asarray(dates)
ports = np.asarray(ports)


now = dt.datetime.now()
changed = False
LAT,LON,NUM,WHEN = [],[],[],[]
Ts= []     # control to avoid diverging Ndays control
cont = 0
for ip in dif_IPs:
   if not changed: changed = False  # if changed=True, then stop checking
   resp = os.popen('grep "%s   " %s'%(ip,ips_file)).read().splitlines()
   if len(resp) == 0:
      LG.debug('No previous entry for ip: %s'%(ip))
      ## No Geo-IP info
      LG.debug('%s from web'%(ip))
      info = geoip.analyze_IP(ip)
      lat,lon = info.coor
      with open(ips_file,'a') as f:
         f.write(ip+'   '+str(lat)+'   '+str(lon)+'   ')
         f.write(now.strftime('%Y   %m   %d') +'\n')
   elif len(resp) == 1:
      LG.debug('1 previous entry for ip: %s'%(ip))
      resp = resp[0]
      lat,lon = map(float,resp.split()[1:3])
      T = dt.datetime.strptime(','.join(resp.split()[-3:]),'%Y,%m,%d')
      Tdelta = (now-T).total_seconds()
      if Tdelta > ndays*60*60*24:
         LG.debug('previous entry from %.1f days ago'%(Tdelta/(60*60*24)))
         LG.debug('%s from web'%(ip))
         info = geoip.analyze_IP(ip)
         lat_new,lon_new = info.coor
         if (lat_new,lon_new) != (lat,lon):
            LG.warning('Geo-IP info changed')
            Ts.append(Tdelta/(60*60*24))  # store only changed dates
            changed = True
            # remove previous data
            com = 'sed -i "/^%s/d" %s'%(resp.split()[0],ips_file)
            LG.debug(com)
            os.system(com)
            with open(ips_file,'a') as f:
               f.write(ip+'   '+str(lat_new)+'   '+str(lon_new)+'   ')
               f.write(now.strftime('%Y   %m   %d') +'\n')
      else: pass ## No need to do anything
   else:  # Duplicated Geo-IP info
      LG.debug('%s previous entries for ip: %s'%(len(resp),ip))
      # remove previous data
      for R in resp:
         com = 'sed -i "/^%s/d" %s'%(R.split()[0],ips_file)
         LG.debug(com)
         os.system(com)
      ## No Geo-IP info
      LG.debug('%s from web'%(ip))
      info = geoip.analyze_IP(ip)
      lat,lon = info.coor
      with open(ips_file,'a') as f:
         f.write(ip+'   '+str(lat)+'   '+str(lon)+'   ')
         f.write(now.strftime('%Y   %m   %d') +'\n')
   num = np.count_nonzero(IPs == ip)
   latest_attempt = np.max(dates[IPs==ip])
   d = (1+(now-latest_attempt).total_seconds())/7200
   LAT.append(lat)
   LON.append(lon)
   NUM.append(num)
   WHEN.append( min(1/d,1) )   # (1,0,0,min(1/d,1)))
   cont += 1

if len(Ts)>0:
   with open('Ndays','w') as f:
      f.write(str(int(min(Ts))+1)+'\n')
   f.close()  # unnecessary?


M = np.vstack((LAT,LON,NUM,WHEN)).transpose()
np.save(here+'/attacks.npy',M)
LG.info('All done')
