#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(18084);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2005-1196");
  script_bugtraq_id(13219);

  script_name(english:"phpBB Knowledge Base Module kb.php cat Parameter SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application affected by a SQL
injection issue.");
  script_set_attribute(attribute:"description", value:
"The installed version of phpBB on the remote host includes the
Knowledge Base module, which does not properly sanitize input to the
'cat' parameter of the 'kb.php' script before using it in SQL queries. 
An attacker can exploit this flaw to modify database queries,
potentially even uncovering user passwords for the application.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/396098");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpbb_group:phpbb");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 Tenable Network Security, Inc.");

  script_dependencies("phpbb_detect.nasl");
  script_require_keys("www/phpBB");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try a simple exploit.
  r = http_send_recv3(method:"GET",item:string(dir, "/kb.php?mode=cat&cat='", SCRIPT_NAME), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we see a syntax error.
  if (egrep(string:res, pattern:string("SQL Error : .+", SCRIPT_NAME, "' at line"), icase:TRUE))
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  }
}
