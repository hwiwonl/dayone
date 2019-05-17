# Browser Exploitation on Linux

## Chromium
* Search `Branch Base Position` at [here](https://omahaproxy.appspot.com/)
* Then search built chromium on [snapshot](https://commondatastorage.googleapis.com/chromium-browser-snapshots/index.html)
* Download it and test :)

### V8
CVE Number | Feature | Keywords | Credit
---------- | ------- | -------- | ------
[CVE-2017-????](./chromium/716044/README.md) | Array.prototype.map | Array, Prototype, OOB write | _halbecaf_
[CVE-2019-????](./chromium/46654/README.md) | JSPromise::TriggerPromiseReactions | JSPromise, TriggerPromiseReactions, Type Confusion | _glazunov_
[CVE-2019-????](./chromium/46748/README.md) | NewFixedDoubleArray | NewFixedDoubleArray, Integer Overflow | _glazunov_