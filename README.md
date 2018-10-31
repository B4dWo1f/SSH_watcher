# SSH watcher

This script provides the tools to watch the ssh server and report possible attacs. It should be added as a CRON job so the attacks are reported as often as desired.\
The execution flow would be:\
1.- ssh.py --> provides a data file containing the ips, geo-location and date-time\
2.- plot_attacks.py --> plots the attacks as a transparent layer with red dots in the attacks locations. The output png image can be overlayed directly on top of mundo.png

## ssh.py
ssh.py scans the systems log (/var/log/auth.log) to look for failed ssh logins. It saves a file (ips.dat) where it stores the ip, the corresponding latitude and longitude and the date-time of the event.

### Parameters
Ndays: [int] number of days to update the geographic information of an ip\
ips_file: [str] name of the file to store the geoip information\
log_file: [str] system's log file. Default = /var/log/auth.log\
log: [str] logger file
