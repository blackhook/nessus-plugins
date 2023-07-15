#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15442);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2004-1580");
  script_bugtraq_id(11337);

  script_name(english:"CubeCart index.php cat_id Parameter SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
SQL injection attack.");
  script_set_attribute(attribute:"description", value:
"There is a SQL injection issue in the remote version of CubeCart that
could allow an attacker to execute arbitrary SQL statements on the
remote host and to potentially overwrite arbitrary files on the remote
system, by sending a malformed value to the 'cat_id' argument of the
file 'index.php'.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2004/Oct/51");
  script_set_attribute(attribute:"see_also", value:"https://forums.cubecart.com/topic/4065-cubecart-202-released/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to CubeCart 2.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cubecart:cubecart");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2022 Tenable Network Security, Inc.");

  script_dependencies("cubecart_detect.nasl");
  script_require_keys("www/cubecart");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if ( ! can_host_php(port:port) ) exit(0, "The web server on port "+port+" does not support PHP");

# Test an install.
install = get_kb_item(string("www/", port, "/cubecart"));
if (isnull(install)) exit(0, "No cubecart installation was found on port "+port);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (isnull(matches)) exit(1, "No cubecart installation was found on port "+port);

 loc = matches[2];

 r = http_send_recv3(method:"GET", port:port, item: loc + "/index.php?cat_id=42'");
 if (isnull(r)) exit(1, "The web server on port "+port+" did not answer");
 res = strcat(r[0], r[1], '\r\n', r[2]);

 if ("mysql_fetch_array()" >< res)
 {
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
 }
else
  exit(0, "No vulnerable cubecart installation was found on port "+port);

