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