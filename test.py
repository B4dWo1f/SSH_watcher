#!/usr/bin/python3
# -*- coding: UTF-8 -*-

import requests
from random import choice

class profile(object):
   """
     Dummy class for pretty printing or future development
   """
   def __init__(self,IP='',hostname='',country='',state='',city='',
                                                          GPS_pos='',dates=[]):
      self.ip = IP
      self.hostname = hostname
      self.country = country
      self.state = state
      self.city = city
      self.coor = GPS_pos
      self.dates = dates
   def __str__(self):
      msg =  '       IP: %s\n'%(self.ip)
      msg += ' hostname: %s\n'%(self.hostname)
      msg += '  country: %s\n'%(self.country)
      msg += '    state: %s\n'%(self.state)
      msg += '     city: %s\n'%(self.city)
      msg += '      GPS: %s,%s\n'%(self.coor[0],self.coor[1])
      D = self.dates
      try: msg += '    dates: %s - %s (%s)'%(D[0],D[-1],len(D))
      except IndexError: msg = msg[0:-1]
      return msg

def analyze_IP(IP):
   """ Randomly chooses a web service to look up the IP information """
   funcs = [ipapi,ipinfo]
   return choice(funcs)(IP)

def ipapi(IP):
   """ Use webservice from ip-api.com to get information about an IP """
   location = requests.get('http://ip-api.com/json/%s'%(IP)).json()
   ## hostname
   try: hostname = location['hostname']
   except: hostname = ''
   ## country
   try: country = location['country']
   except: country = ''
   ## city
   try: city = location['city']
   except: city = ''
   ## State
   try: state = location['region']
   except: state = ''
   ## GPS position
   try:
      lat,lon = location['lat'],location['lon']
      GPS_pos = (float(lat),float(lon))
   except: GPS_pos = (0,0)
   return profile(IP,str(hostname),str(country),str(state),str(city),GPS_pos)

def ipinfo(IP):
   """ Use webservice from ipinfo.io to get information about an IP """
   location = requests.get('http://ipinfo.io/%s'%(IP)).json()
   ## hostname
   try: hostname = location['hostname']
   except: hostname = ''
   ## country
   try: country = location['country']
   except: country = ''
   ## city
   try: city = location['city']
   except: city = ''
   ## State
   try: state = location['region']
   except: state = ''
   ## GPS position
   try:
      lat,lon = location['loc'].split(',')
      GPS_pos = (float(lat),float(lon))
   except: GPS_pos = (0,0)
   return profile(IP,str(hostname),str(country),str(state),str(city),GPS_pos)
