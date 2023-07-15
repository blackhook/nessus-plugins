#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(17260);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2005-0606", "CVE-2005-0607");
  script_bugtraq_id(12658);

  script_name(english:"CubeCart < 2.0.6 settings.inc.php Multiple Script XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple issues.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of CubeCart installed on the
remote host suffers from multiple cross-site scripting and path
disclosure vulnerabilities due to a failure to sanitize user input in
'admin/settings.inc.php', which is used by various scripts.");
  # http://lostmon.blogspot.com/2005/02/cubecart-20x-multiple-variable-xss.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b563b931");
  script_set_attribute(attribute:"see_also", value:"https://forums.cubecart.com/topic/6032-cubecart-206-released/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to CubeCart 2.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cubecart:cubecart");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 Tenable Network Security, Inc.");

  script_dependencies("cubecart_detect.nasl");
  script_require_keys("www/cubecart");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(1, "The web server on port "+port+" does not support PHP");


# Test an install.
install = get_kb_item(string("www/", port, "/cubecart"));
if (isnull(install)) exit(0, "cubecart was not detected on port "+port);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # If it's CubeCart 2.0.0 - 2.0.5, there's a problem.
  if (ver =~ "^2\.0\.[0-5]")
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
