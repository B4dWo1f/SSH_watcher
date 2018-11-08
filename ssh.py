#!/usr/bin/python3
# -*- coding: UTF-8 -*-

"""
  This code will extract and simplify the log file for ssh failed logins and
  port scans...
"""
from os.path import expanduser
import os
here = os.path.dirname(os.path.realpath(__file__))  # script folder
HOME = os.getenv('HOME')
USER = os.getenv('USER')

from configparser import ConfigParser, ExtendedInterpolation
config = ConfigParser(inline_comment_prefixes='#')
config._interpolation = ExtendedInterpolation()
config.read(here+'/config.ini')

parms = config['parameters']
ndays = int(parms['Ndays'])
ips_file = expanduser(parms['ips_file'])
log_file = expanduser(parms['log_file'])
log = expanduser(parms['log'])

## personal system-wide log tools and decorators, which can be found here:
# https://github.com/B4dWo1f/bin/blob/master/log_help.py
import log_help
import logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)s:%(levelname)s - %(message)s',
                    datefmt='%Y/%m/%d-%H:%M:%S',
                    filename=log, filemode='w')
LG = logging.getLogger('main')
log_help.screen_handler(LG)

# dependence on my geoip library, which can be found here:
# https://github.com/B4dWo1f/bin/blob/master/geoip.py
import geoip
import parser as func
import datetime as dt
import numpy as np
import sys


### Standard input to select file and hostname, mainly for debugging
## TODO: maybe argparse this
#try: log_file = sys.argv[1]
#except IndexError: log_file = '/var/log/auth.log'
#
#try: hostname = sys.argv[2]
#except IndexError: hostname = os.uname()[1]

#ips_file = here + '/ips.dat'  # Local database of IP-GPS
#ndays_file = here+'/Ndays'
#ndays = int(open(ndays_file).read())  # Number of days to update IP-GPS data

## Read file and  Analyze the sshd entries
sshd_logins = os.popen('grep -a " sshd\[" %s'%(log_file)).read().splitlines()

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
# attacks
logins = failed_logins + alert_logins + port_scans
LG.info('Evaluating %s attempts'%(len(logins)))
attempts = []
for l in logins: # TODO Split contributions
   resp = func.parse_attempt(l) #,hostname=hostname)
   if resp != None: attempts.append(resp)
# accepted
LG.info('Evaluating %s successful logins'%(len(accepted_logins)))
logins = []
for l in accepted_logins: # TODO Split contributions
   resp = func.parse_attempt(l) #,hostname=hostname)
   if resp != None: logins.append(resp)


## Extract all the IPs
IPs = [T.ip for T in attempts]
dates = [T.date for T in attempts]
ports = [T.port for T in attempts]
dif_IPs = list(set(IPs))


LAT, LON, NUM, WHEN, Ts= func.attacks_info(IPs,dates,ports,ips_file,ndays)

if len(Ts)>0:
   with open(ndays_file,'w') as f:
      f.write(str(int(min(Ts))+1)+'\n')
   f.close()  # unnecessary?

M = np.vstack((LAT,LON,NUM,WHEN)).transpose()
np.save(here+'/attacks.npy',M)
LG.info('Attacks done')



## Extract all the IPs
IPs = [T.ip for T in logins]
dates = [T.date for T in logins]
ports = [T.port for T in logins]

LAT, LON, NUM, WHEN, Ts= func.attacks_info(IPs,dates,ports,ips_file,ndays)

if len(Ts)>0:
   with open(ndays_file,'w') as f:
      f.write(str(int(min(Ts))+1)+'\n')
   f.close()  # unnecessary?

M = np.vstack((LAT,LON,NUM,WHEN)).transpose()
np.save(here+'/logins.npy',M)
LG.info('All done')
