#%NASL_MIN_LEVEL 70300
#
# This script was written by John Lampe <j_lampe@bellsouth.net>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, changed family (2/04/09)
# - Title touch-up (9/18/09)
# - Title standardization (10/28/09)
# - Add MSKB script_xref (8/29/17)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10699);
  script_version("1.51");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2001-0341");
  script_bugtraq_id(2906);
  script_xref(name:"MSKB", value:"300477");
  script_xref(name:"MSFT", value:"MS01-035");

  script_name(english:"MS01-035: Microsoft IIS FrontPage fp30reg.dll Remote Overflow (uncredentialed check)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a buffer overflow attack.");
  script_set_attribute(attribute:"description", value:
"Microsoft IIS, running Frontpage extensions, is vulnerable to a remote
buffer overflow attack.  An attacker, exploiting this bug, may gain
access to confidential data, critical business processes, and elevated
privileges on the attached network.");
  # http://web.archive.org/web/20101012083646/http://www.microsoft.com/technet/security/Bulletin/MS01-035.mspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb5e7e9d");
  script_set_attribute(attribute:"solution", value:
"Install either SP4 for Windows 2000 or apply the fix described in
Microsoft Bulletin MS01-035.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/06/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:internet_information_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2001-2022 John Lampe");

  script_dependencies("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80, embedded:TRUE);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) 
	exit(0);



#Make sure app is alive...
mystring = string("HEAD / HTTP/1.0\r\n\r\n");
if(get_port_state(port)) 
{
    mysoc = open_sock_tcp(port);
    if (! mysoc)
	exit(0);
    send(socket:mysoc, data:mystring);
    incoming = http_recv(socket:mysoc);
    if(!incoming) 
	exit(0);
    close(mysoc);
}


mystring= string ("GET /_vti_bin/_vti_aut/fp30reg.dll?" , crap(260), " HTTP/1.0\r\n\r\n");
if(get_port_state(port)) 
{
        mysoc = open_sock_tcp(port);
	if (! mysoc)
		exit(0);
        send(socket:mysoc, data:mystring);
        incoming=http_recv(socket:mysoc);
        match = egrep(pattern:".*The remote procedure call failed*" , string:incoming);
        if(match) 
		security_hole(port);
        close (mysoc);
}

