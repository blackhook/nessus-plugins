#%NASL_MIN_LEVEL 70300
#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, removed francais (3/30/2009)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10839);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2002-2029");
  script_bugtraq_id(3786);

  script_name(english:"Apache Win32 ScriptAlias php.exe Arbitrary File Access");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be read on the remote host.");
  script_set_attribute(attribute:"description", value:
"A configuration vulnerability exists for PHP.EXE cgi running on Apache 
for Win32 platforms. It is reported that the installation text recommends 
configuration options in httpd.conf that create a security vulnerability, 
allowing arbitrary files to be read from the host running PHP. Remote users 
can directly execute the PHP binary:

http://www.somehost.com/php/php.exe?c:\winnt\win.ini");
  script_set_attribute(attribute:"see_also", value:"http://www.securitytracker.com/alerts/2002/Jan/1003104.html");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net");
  script_set_attribute(attribute:"solution", value:
"Obtain the latest version from http://www.php.net");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/01/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2002-2022 Matt Moore");

  script_dependencies("find_service1.nasl", "http_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

# Check starts here

include("http_func.inc");

port = get_http_port(default:80, embedded:TRUE);

if(get_port_state(port))
{ 	      
 if ( ! can_host_php(port:port) ) exit(0);
 req = http_get(item:"/php/php.exe?c:\winnt\win.ini", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("[windows]" >< r)	
 	security_warning(port);

 }
}
