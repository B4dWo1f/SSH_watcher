#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import re
import datetime as dt


class attempt(object):
   """
     Dummy class for pretty printing or future development.
     an attempt is understood as the useful information in an entry in
     the file /var/log/auth.log
   """
   def __init__(self,date,usr,ip,port):
      self.usr = usr
      self.date = date
      self.ip = ip
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
   elif 'Connection closed' in event:
      p = r'Connection closed by (\S+.\S+.\S+.\S+) \[preauth\]'
      m = re.search(p,event)
      ip, = m.groups()
   elif 'Did not receive' in event:
      p = r'Did not receive identification string from (\S+.\S+.\S+.\S+)'
      m = re.search(p,event)
      ip, = m.groups()
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
      p = r'Invalid user *(\w+) from (\S+.\S+.\S+.\S+)'
      m = re.search(p,event) #   , re.UNICODE)
      user,ip = m.groups()
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


#import os
#HOSTNAME = os.uname()[1]
#def parse_attempt_old(line,hostname=HOSTNAME):
#   """ Parses an auth.log [sshd] line extracting date, user, ip, port """
#   #TODO replace this with re for regular expressions
#   ## Header
#   header = line.split(': ')[0]
#   date = header.split('%s'%(hostname))[0].lstrip().rstrip()
#   date = dt.datetime.strptime(date, '%b %d %H:%M:%S')
#   date = date.replace(year=dt.datetime.now().year)
#   ## Body
#   body = ': '.join( line.split(': ')[1:] )
#   for x in body.split():
#      try: ip = IP.ip_address(x.replace(':','').replace('[','').replace(']',''))
#      except ValueError: pass
#   if 'Invalid user' in body:
#      user = body.replace('Invalid user','').split()[0]
#      port = '***'
#   elif 'Failed password for' in body:
#      user = body.replace('Failed password for invalid','').split()[0]
#      port = body.split('port')[-1].split()[0]
#   elif 'Received disconnect from ' in body:
#      lista = body.split(':')
#      user = '****'
#      port = '****'
#   elif 'PAM' in body:
#      lista = body.split('=')
#      if len(lista) == 8:
#         user = lista[-1]
#         port = '****'
#      elif len(lista) == 7:
#         user = '****'
#         port = '****'
#      else: return None
#   elif 'Connection closed by ' in body or\
#        'reverse mapping checking getaddrinfo' in body or\
#        'Did not receive identification string from' in body:
#      user = '****'
#      port = '****'
#   else:
#      print('*'*33,'Unkown Case','*'*33,'\n',line)
#      exit()
#   return attempt(date,user,str(ip),port)
