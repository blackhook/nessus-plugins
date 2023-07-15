#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10618);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2001-0302", "CVE-2001-0303");
  script_bugtraq_id(2381);

  script_name(english:"Pi3Web tstisap.dll Long URL Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a script that is affected by several
issues.");
  script_set_attribute(attribute:"description", value:
"The '/isapi/tstisapi.dll' cgi is installed.  This CGI has a well-known
security flaw that lets anyone execute arbitrary commands with the
privileges of the http service. 

In addition, it discloses the physical path to the web root if an
invalid URL is requested.");
  script_set_attribute(attribute:"solution", value:
"Remove the script from /isapi.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/02/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pi3:pi3web");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2001-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "find_service1.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( "Pi3Web/" >!< banner ) exit(0);

w = http_send_recv3(method:"GET", item:"/isapi/tstisapi.dll", port:port);
r = strcat(r[0], r[1], '\r\n', r[2]);
if ("SERVER_SOFTWARE=Pi3Web/1.0.1" >< r)security_hole(port);

