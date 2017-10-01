#!/usr/bin/python3
# -*- coding: UTF-8 -*-

"""
  This code will extract and simplify the log file for ssh failed logins and
  port scans...
"""

import test as geoip    # Import personal geoip
import attacks as func
import datetime as dt
import numpy as np
import os
here = os.path.dirname(os.path.realpath(__file__))  # script folder
HOME = os.getenv('HOME')
USER = os.getenv('USER')
hostname = os.uname()[1]
hostname = 'kastercloud'
#cwd = os.getcwd()   # execution folder


log_file = '/var/log/auth.log'
log_file = 'auth.log'

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
attempts = []
for l in failed_logins + alert_logins + port_scans: # TODO Split contributions
   resp = func.parse_attempt(l,hostname=hostname)
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
LAT,LON,NUM,WHEN = [],[],[],[]
for ip in dif_IPs:
   try:   # Try to find local directory of IP-GPS
      resp = os.popen('grep "%s   " %s'%(ip,'ips.dat')).read()
      lat,lon = map(float,resp.split()[1:])
   except ValueError:
      info = geoip.analyze_IP(ip)
      lat,lon = info.coor
      f = open('ips.dat','a')  # This file should be deleted ~ once a month
      f.write(ip+'   '+str(lat)+'   '+str(lon)+'\n')
      f.close()
   num = np.count_nonzero(IPs == ip)
   latest_attempt = np.max(dates[IPs==ip])
   d = (1+(now-latest_attempt).total_seconds())/7200
   LAT.append(lat)
   LON.append(lon)
   NUM.append(num)
   WHEN.append( min(1/d,1) )   # (1,0,0,min(1/d,1)))

M = np.vstack((LAT,LON,NUM,WHEN)).transpose()
np.save(here+'/attacks.npy',M)
