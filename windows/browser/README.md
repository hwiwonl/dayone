# Browser Exploitation on Windows

## Chromium
* Search `Branch Base Position` at [here](https://omahaproxy.appspot.com/)
* Then search built chromium on [snapshot](https://commondatastorage.googleapis.com/chromium-browser-snapshots/index.html)
* Download it and test :)

### V8
CVE Number | Feature | Keywords | Credit
---------- | ------- | -------- | ------
[CVE-2019-5825](./chromium/941743/README.md) | Array.prototype.map | Array, prototype, map OOB write | _Tencent Keen_
[CVE-2016-1646](./chromium/594574/README.md) | Array.concat | Array, concat, OOB access | _Tencent Keen_
[CVE-2017-????](./chromium/746946/README.md) | JIT | TurboFan, Type Confusion | _SecuriTeam Secure Disclosure_
[CVE-2017-15399](./chromium/201715399/README.md) | WebAssembly | WebAssembly | _Zhao Qixun (Qihoo 360 Vulcan Team)_
[CVE-2017-5070](./chromium/20175070/README.md) | crankshaft | Type Confusion | _Zhao Qixun (Qihoo 360 Vulcan Team)_

## IE
### VBScript

### jscript

## Mozilla (firefox)

### spidermonkey