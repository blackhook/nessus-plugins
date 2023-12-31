#%NASL_MIN_LEVEL 70300
#
# This script was written by Geoffroy Raimbault <graimbault@lynx-technologies.com>
#
# www.lynx-technologies.com
#
# See the Nessus Scripts License for details
#
# Changes by Tenable:
# - Revised script name (12/19/2008)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11142);
  script_version("1.32");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(5900);

  script_name(english:"Microsoft IIS IDC Extension XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting 
vulnerability.");
  script_set_attribute(attribute:"description", value:
"This IIS Server appears to be vulnerable to a cross-site scripting
attack due to an error in the handling of overly-long requests on an 
idc file.  It is possible to inject JavaScript in the URL, that will
appear in the resulting page.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Windows 2000 SP3 or higher, as this reportedly fixes the 
issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value:"2002/10/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2002-2022 Geoffroy Raimbault/Lynx Technologies");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl", "www_fingerprinting_hmap.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80, embedded:TRUE);

if(!get_port_state(port)) exit(0);
sig = get_http_banner(port:port);
if ( sig && "Server: Microsoft/IIS" >!< sig ) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

# We construct the malicious URL with an overlong idc filename
filename = string("/<script></script>",crap(334),".idc");
req = http_get(item:filename, port:port);

r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
str="<script></script>";
if((str >< r))
{
 security_warning(port);
 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}

