# CVE-2018-8174
* Date : May 2018
* Credit : SMGORELIK

## Description
* Microsoft Internet Explorer 11 (Windows 7 x64/x86) - vbscript Code Execution


## MEMO
- [x] Enable page heap

**poc.html** 
```
0:007> kb
ChildEBP RetAddr  Args to Child              
WARNING: Frame IP not in any known module. Following frames may be wrong.
02b1b7f0 77bc4977 00deb900 00000002 02378080 0xe000
02b1b804 77bde325 02378080 02378080 02318100 OLEAUT32!VariantClear+0xb9
02b1b818 77bddfb3 02318100 02378080 00000020 OLEAUT32!ReleaseResources+0xa3
02b1b840 77be5d2d 02318100 00000001 02b1b864 OLEAUT32!_SafeArrayDestroyData+0x48
02b1b850 77be5d13 02318100 00df7e0c 02318100 OLEAUT32!SafeArrayDestroyData+0xf
02b1b864 710f52d0 02318100 02b1b88c 710f5280 OLEAUT32!Thunk_SafeArrayDestroyData+0x39
02b1b878 71094787 02b1baa0 00000001 00df75c8 vbscript!VbsErase+0x50
02b1b894 710957cb 02b1baa0 00000001 00df75c8 vbscript!StaticEntryPoint::Call+0x2f
02b1bae4 7109526e 02b1be50 7948fc4d 00df75f8 vbscript!CScriptRuntime::RunNoEH+0x1d74
02b1bb34 7109518b 02b1be50 02b1bc60 71095080 vbscript!CScriptRuntime::Run+0xc3
02b1bc44 710957cb 02b1be50 00000000 00df75f8 vbscript!CScriptEntryPoint::Call+0x10b
02b1be94 7109526e 02b1c020 7948f99d 00000000 vbscript!CScriptRuntime::RunNoEH+0x1d74
02b1bee4 7109518b 02b1c020 00d87308 00da1420 vbscript!CScriptRuntime::Run+0xc3
02b1bff4 710959bd 02b1c020 00000000 00000000 vbscript!CScriptEntryPoint::Call+0x10b
02b1c068 71095c6b 00d87308 02b1c2b0 00000000 vbscript!CSession::Execute+0x156
02b1c0b8 710b8ed8 02b1c2b0 02b1c2d0 02b1c190 vbscript!COleScript::ExecutePendingScripts+0x14f
02b1c134 7109c1d9 00338584 0237279c 7109c1b0 vbscript!COleScript::ParseScriptTextCore+0x23e
02b1c160 664458a5 00df182c 00338584 0237279c vbscript!COleScript::ParseScriptText+0x29
...

0:007> u 77bde320
OLEAUT32!ReleaseResources+0x9e:
77bde320 e8895bfeff      call    OLEAUT32!VariantClear (77bc3eae)
77bde325 83c610          add     esi,10h
77bde328 4f              dec     edi
77bde329 0f84b1fbffff    je      OLEAUT32!ReleaseResources+0xd1 (77bddee0)
77bde32f ebee            jmp     OLEAUT32!ReleaseResources+0x9d (77bde31f)
77bde331 90              nop
77bde332 90              nop
77bde333 90              nop

0:007> u 77bc4973
OLEAUT32!VariantClear+0xb5:
77bc4973 50              push    eax
77bc4974 ff5108          call    dword ptr [ecx+8]
77bc4977 e949f5ffff      jmp     OLEAUT32!VariantClear+0xc3 (77bc3ec5)
77bc497c 57              push    edi
77bc497d e8f8feffff      call    OLEAUT32!IsLegalVartype (77bc487a)
77bc4982 85c0            test    eax,eax
77bc4984 7d82            jge     OLEAUT32!VariantCopy+0x25 (77bc4908)
77bc4986 ebd8            jmp     OLEAUT32!VariantCopy+0x164 (77bc4960)

0:007> r
eax=00deb900 ebx=00000020 ecx=71090033 edx=00000000 esi=02378080 edi=00000009
eip=0000e000 esp=02b1b7f4 ebp=02b1b804 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
0000e000 ??              ???
0:007> dd ecx+8
7109003b  0000e000 ba1f0e00 09b4000e 01b821cd
7109004b  5421cd4c 20736968 676f7270 206d6172
7109005b  6e6e6163 6220746f 75722065 6e69206e
7109006b  534f4420 646f6d20 0d0d2e65 0000240a
7109007b  00000000 3c8dcb00 52ec8f0d 52ec8f5e
7109008b  52ec8f5e 9c13525e 52ec995e 9f13525e
7109009b  52ec885e 53ec8f5e 52ec665e 9913525e
710900ab  52ec865e 9813525e 52ec8e5e 8a13525e
0:007> !heap -p -a eax
    address 00deb900 found in
    _HEAP @ 5a0000
      HEAP_ENTRY Size Prev Flags    UserPtr UserSize - state
        00deb8f8 0007 0000  [00]   00deb900    00030 - (free)
```

**poc2.html**
```
(af4.948): Access violation - code c0000005 (!!! second chance !!!)
eax=0f73bdd0 ebx=65742e00 ecx=65742e00 edx=0c4c5198 esi=0c4c5198 edi=0f73bdb0
eip=65742e00 esp=0f73bda0 ebp=0f73bdd8 iopl=0         nv up ei ng nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010283
65742e00 ??              ???
0:029> kb
ChildEBP RetAddr  Args to Child              
WARNING: Frame IP not in any known module. Following frames may be wrong.
0f73bd9c 6df828c0 0c4c5198 6df82114 0f73bdd0 0x65742e00
0f73bdd8 6df8350c 0f73bfb0 0f73bec8 025a13e8 vbscript!GetDispatchDispID+0x40
0f73c01c 6df8526e 0f73c1a8 d0964da6 00000000 vbscript!CScriptRuntime::RunNoEH+0x1951
0f73c06c 6df8518b 0f73c1a8 025172e0 02531a80 vbscript!CScriptRuntime::Run+0xc3
0f73c17c 6df859bd 0f73c1a8 00000000 00000000 vbscript!CScriptEntryPoint::Call+0x10b
0f73c1f0 6df85c6b 025172e0 0f73c438 00000000 vbscript!CSession::Execute+0x156
0f73c240 6dfa8ed8 0f73c438 0f73c458 0f73c318 vbscript!COleScript::ExecutePendingScripts+0x14f
0f73c2bc 6df8c1d9 08117ed4 0c9610bc 6df8c1b0 vbscript!COleScript::ParseScriptTextCore+0x23e
0f73c2e8 664458a5 025a13ec 08117ed4 0c9610bc vbscript!COleScript::ParseScriptText+0x29
0f73c320 667525ae 08117ed4 00000000 00000000 MSHTML!CActiveScriptHolder::ParseScriptText+0x51
0f73c390 66446669 0c79c128 0b1c5ed8 00000000 MSHTML!CScriptCollection::ParseScriptText+0x193
0f73c47c 66446204 00000000 00000000 00000000 MSHTML!CScriptData::CommitCode+0x370
0f73c4f8 66446ca4 0f73c520 66446b80 064543f0 MSHTML!CScriptData::Execute+0x2a9
0f73c518 66252c60 064543f0 00000000 08024680 MSHTML!CHtmScriptParseCtx::Execute+0x130
0f73c5a0 66186343 00d29676 00000000 08024680 MSHTML!CHtmParseBase::Execute+0x196
0f73c5bc 661860f8 00000002 064543f0 6620f900 MSHTML!CHtmPost::Broadcast+0x153
0f73c6f4 6620fc08 00d29676 0842fec8 08024680 MSHTML!CHtmPost::Exec+0x5d9
0f73c714 6620fb6e 00d29676 08024680 0842fec8 MSHTML!CHtmPost::Run+0x3d
0f73c730 6621a826 08024680 08024680 80000000 MSHTML!PostManExecute+0x61
0f73c744 6621b4f8 6621b4c0 0f73c784 0842fec8 MSHTML!PostManResume+0x7b
0f73c774 66204027 07fde6f0 08024680 0cba86f8 MSHTML!CHtmPost::OnDwnChanCallback+0x38
0f73c78c 6608e541 07fde6f0 00000000 0842fec8 MSHTML!CDwnChan::OnMethodCall+0x3e
0f73c7d8 6608de4a d9174ccd 0f73c8a4 00008002 MSHTML!GlobalWndOnMethodCall+0x16d
0f73c828 7695c4e7 0017009c 00008002 00000000 MSHTML!GlobalWndProc+0x2e5
0f73c854 7695c5e7 6608d020 0017009c 00008002 user32!InternalCallWinProc+0x23
0f73c8cc 7695cc19 00000000 6608d020 0017009c user32!UserCallWinProcCheckWow+0x14b
0f73c92c 7695cc70 6608d020 00000000 0f73fb08 user32!DispatchMessageWorker+0x35e
0f73c93c 6b86f7c8 0f73c97c 025f2090 03076b98 user32!DispatchMessageW+0xf
0f73fb08 6b9bf738 0f73fbd4 6b9bf3b0 02561558 IEFRAME!CTabWindow::_TabWindowThreadProc+0x464
0f73fbc8 7651e61c 025f2090 0f73fbec 6b9c30d0 IEFRAME!LCIETab_ThreadProc+0x37b
0f73fbe0 733e3991 02561558 00000000 00000000 iertutil!_IsoThreadProc_WrapperToReleaseScope+0x1c
0f73fc18 7622ed6c 0cad0fb0 0f73fc64 77a837eb IEShims!NS_CreateThread::DesktopIE_ThreadProc+0x94
0f73fc24 77a837eb 0cad0fb0 780ef0a2 00000000 kernel32!BaseThreadInitThunk+0xe
0f73fc64 77a837be 733e3900 0cad0fb0 ffffffff ntdll!__RtlUserThreadStart+0x70
0f73fc7c 00000000 733e3900 0cad0fb0 00000000 ntdll!_RtlUserThreadStart+0x1b
0:029> u 6df828c0 
vbscript!GetDispatchDispID+0x40:
6df828c0 3bfc            cmp     edi,esp
6df828c2 0f85f6d30200    jne     vbscript!GetDispatchDispID+0x44 (6dfafcbe)
6df828c8 8b7dfc          mov     edi,dword ptr [ebp-4]
6df828cb 85c0            test    eax,eax
6df828cd 0f8930600200    jns     vbscript!GetDispatchDispID+0xed (6dfa8903)
6df828d3 8b4508          mov     eax,dword ptr [ebp+8]
6df828d6 ff3550a0fe6d    push    dword ptr [vbscript!g_luTls (6dfea050)]
6df828dc 8b00            mov     eax,dword ptr [eax]
0:029> u 6df828be
vbscript!GetDispatchDispID+0x3e:
6df828be ffd3            call    ebx
6df828c0 3bfc            cmp     edi,esp
6df828c2 0f85f6d30200    jne     vbscript!GetDispatchDispID+0x44 (6dfafcbe)
6df828c8 8b7dfc          mov     edi,dword ptr [ebp-4]
6df828cb 85c0            test    eax,eax
6df828cd 0f8930600200    jns     vbscript!GetDispatchDispID+0xed (6dfa8903)
6df828d3 8b4508          mov     eax,dword ptr [ebp+8]
6df828d6 ff3550a0fe6d    push    dword ptr [vbscript!g_luTls (6dfea050)]
```

## Reference
- [Exploit-DB](https://www.exploit-db.com/exploits/44741)
- [Root cause analysis of the latest Internet Explorer zero day – CVE-2018-8174](https://securelist.com/root-cause-analysis-of-cve-2018-8174/85486/)
- [Analysis of CVE-2018-8174 exploitation](https://securelist.com/delving-deep-into-vbscript-analysis-of-cve-2018-8174-exploitation/86333/)
- [Analysis of CVE-2018-8174 VBScript 0day and APT actor related to Office targeted attack](http://blogs.360.cn/post/cve-2018-8174-en.html)
- [PoC github](https://github.com/piotrflorczyk/cve-2018-8174_analysis/blob/master/analysis.vbs)