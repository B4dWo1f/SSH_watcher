#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import re
import datetime as dt
import ipaddress as IP
import logging
LG = logging.getLogger(__name__)   # Logger for this module


class attempt(object):
   """
     Dummy class for pretty printing or future development.
     an attempt is understood as the useful information in an entry in
     the file /var/log/auth.log
   """
   def __init__(self,date,usr,ip,port):
      self.usr = usr
      self.date = date
      self.ip = IP.ip_address(ip)
      self.port = port
   def __str__(self):
      msg = 'Date: %s\n'%(self.date)
      msg += 'User: %s\n'%(self.usr)
      msg += 'IP: %s (%s)\n'%(self.ip,self.port)
      return msg

class attacker():
   """
     Dummy class for pretty printing or future development.
     an attacker is identified by the ip by thich the attack was carried out.
     The geographic information is stored.
   """
   def __init__(self,ip,country='',state='',city='',GPS_pos=('',''),Ntot=0):
      self.ip = ip
      self.country = country
      self.state = state
      self.city = city
      self.GPS_pos = GPS_pos
      self.Ntot = Ntot
   def __str__(self):
      msg = 'IP: %s\n'%(self.ip)
      msg += '  Country: %s\n'%(self.country)
      msg += '  State: %s\n'%(self.state)
      msg += '  City: %s\n'%(self.city)
      msg += '  GPS position: %s\n'%(self.GPS_pos)
      msg += '  # Attacks: %s\n'%(self.Ntot)
      return msg


import ipaddress as IP
def parse_attempt(line):
   """
     Regular expression matching for the lines with focus on user, ip and port.
   TODO: pam_unix, input_userauth_request and fatal to be studied to figure
   out what information can be extracted
   """
   user,port,ip = '','',''   # Initialize
   pattern = r'(\w+ *\S+ \S+:\S+:\S+) (\w+) sshd\[(\S+)\]: ([ ^\W\w\d_ ]*)'
   dt_format = '%b %d %H:%M:%S'
   match = re.search(pattern,line)
   date,hostname,ind,event = match.groups()
   date = dt.datetime.strptime(date, '%b %d %H:%M:%S')
   date = date.replace(year=dt.datetime.now().year)  # add year
   ## Parse Options
   if 'Accepted publickey for' in event:
      p = r'Accepted publickey for (\w+) from (\S+.\S+.\S+.\S+) port (\S+) '
      p += r'ssh2: RSA ([ ^\W\w\d_ ]*)'
      m = re.search(p,event)
      user,ip,port,fingerprint = m.groups()
   elif 'Accepted password for ' in event:
      p = r'Accepted password for (\w+) from (\S+.\S+.\S+.\S+) port (\S+) ssh2'
      m = re.search(p,event)
      user,ip,port = m.groups()
   elif 'Connection closed' in event:
      p = r'Connection closed by (\S+.\S+.\S+.\S+) port (\S+) \[preauth\]'
      m = re.search(p,event)
      ip,port, = m.groups()
   elif 'Did not receive' in event:
      #p = r'Did not receive identification string from (\S+.\S+.\S+.\S+)'
      p = r'Did not receive identification string from (\S+.\S+.\S+.\S+) port (\S+)'
      m = re.search(p,event)
      ip,port = m.groups()
   elif 'PAM' in event:
      p = r'PAM (\S+) more authentication (\w+); logname= uid=0 euid=0 '
      p += r'tty=ssh ruser= rhost=(\S+.\S+.\S+.\S+)  user=(\w+)'
      m = re.search(p,event)
      _,_,ip,user = m.groups()
   elif 'Received disconnect from' in event:
      p = r'Received disconnect from (\S+.\S+.\S+.\S+): (\S+): ([ ^\W\w\d_ ]*)'
      m = re.search(p,event)
      ip,_,_ = m.groups()
   elif 'reverse mapping checking' in event:
      p = r'reverse mapping checking getaddrinfo for ([ ^\W\w\d_ ]*) '
      p += r'\[(\S+.\S+.\S+.\S+)\] failed - POSSIBLE BREAK-IN ATTEMPT!'
      m = re.search(p,event)
      host,ip = m.groups()
   elif 'Invalid user' in event:
      try:
         #p = r'Invalid user *([ ^\W\w\d_ ]*) from (\S+.\S+.\S+.\S+)'
         p = r'Invalid user *([ ^\W\w\d_ ]*) from (\S+.\S+.\S+.\S+) port (\S+)'
         m = re.search(p,event) #   , re.UNICODE)
         user,ip,port = m.groups()
      except AttributeError: # in case of empty user
         p = r'Invalid user *from (\S+.\S+.\S+.\S+)'
         m = re.search(p,event) #   , re.UNICODE)
         ip, = m.groups()
   elif 'Failed password' in event:
      p = r'Failed password for ([ ^\W\w\d_ ]*) from (\S+.\S+.\S+.\S+) '
      p += r'port (\S+) ssh2'
      m = re.search(p,event)
      user,ip,port = m.groups()
   elif 'Failed none' in event:
      p = r'Failed none for invalid user (\w+) from (\S+.\S+.\S+.\S+) '
      p += r'port (\S+) ssh2'
      m = re.search(p,event)
      user,ip,port = m.groups()
   ## TODO study these cases
   elif 'pam_unix' in event: return None
   elif 'input_userauth_request' in event: return None
   elif 'fatal:' in event: return None
   else:
      print('Unknown options')
      print(line)
      exit()
   return attempt(date,user,str(ip),port)



################################################################################

import geoip
import os
import numpy as np

def attacks_info(IPs,dates,ports,ips_file,ndays):
   now = dt.datetime.utcnow()
   dif_IPs = list(set(IPs))

   ## To array
   IPs = np.asarray(IPs)
   dates = np.asarray(dates)
   ports = np.asarray(ports)
   changed = False
   LAT,LON,NUM,WHEN = [],[],[],[]
   Ts= []     # control to avoid diverging Ndays control
   cont = 0
   for ip in dif_IPs:
      if ip.is_private:
         LG.debug(str(ip)+' is private')
         continue
      if not changed: changed = False  # if changed=True, then stop checking
      resp = os.popen('grep "%s   " %s'%(ip,ips_file)).read().splitlines()
      if len(resp) == 0:
         LG.debug('No previous entry for ip: %s'%(ip))
         ## No Geo-IP info
         LG.debug('%s from web'%(ip))
         info = geoip.analyze_IP(ip)
         lat,lon = info.coor
         with open(ips_file,'a') as f:
            f.write(str(ip)+'   '+str(lat)+'   '+str(lon)+'   ')
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
   return LAT, LON, NUM, WHEN, Ts
