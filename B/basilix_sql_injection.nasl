#%NASL_MIN_LEVEL 70300
#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


include('deprecated_nasl_level.inc');
include('compat.inc');

if (description) {
  script_id(14219);
  script_version("1.22");

  script_cve_id("CVE-2002-1709");
  script_bugtraq_id(5061);

  name["english"] = "Basilix Webmail id Variable SQL Injection";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains PHP scripts that are prone to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a BasiliX version 1.1.0 or
lower.  Such versions are potentially vulnerable to SQL injection
attacks depending on the version of PHP installed." );
 # https://web.archive.org/web/20051125141124/http://archives.neohapsis.com/archives/vulnwatch/2002-q2/0117.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3972e49" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BasiliX version 1.1.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/06/18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for SQL injection vulnerability in BasiliX";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2021 George A. Theall");

  script_dependencies("basilix_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/basilix");
  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80, embedded:TRUE);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/basilix"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^(0\..*|1\.(0.*|1\.0))$") {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
