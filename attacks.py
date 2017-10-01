#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import os
import datetime as dt
HOSTNAME = os.uname()[1]


class attempt():
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
def parse_attempt(line,hostname=HOSTNAME):
   """ Parses an auth.log [sshd] line extracting date, user, ip, port """
   #TODO replace this with re for regular expressions
   ## Header
   header = line.split(': ')[0]
   date = header.split('%s'%(hostname))[0].lstrip().rstrip()
   date = dt.datetime.strptime(date, '%b %d %H:%M:%S')
   date = date.replace(year=dt.datetime.now().year)
   ## Body
   body = ': '.join( line.split(': ')[1:] )
   for x in body.split():
      try: ip = IP.ip_address(x.replace(':','').replace('[','').replace(']',''))
      except ValueError: pass
   if 'Invalid user' in body:
      user = body.replace('Invalid user','').split()[0]
      port = '***'
   elif 'Failed password for' in body:
      user = body.replace('Failed password for invalid','').split()[0]
      port = body.split('port')[-1].split()[0]
   elif 'Received disconnect from ' in body:
      lista = body.split(':')
      user = '****'
      port = '****'
   elif 'PAM' in body:
      lista = body.split('=')
      if len(lista) == 8:
         user = lista[-1]
         port = '****'
      elif len(lista) == 7:
         user = '****'
         port = '****'
      else: return None
   elif 'Connection closed by ' in body or\
        'reverse mapping checking getaddrinfo' in body or\
        'Did not receive identification string from' in body:
      user = '****'
      port = '****'
   else:
      print('*'*33,'Unkown Case','*'*33,'\n',line)
      exit()
   return attempt(date,user,str(ip),port)
