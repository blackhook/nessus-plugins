#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(18636);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(14166, 14172);

  script_name(english:"phpWebSite <= 0.10.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to SQL
injection and directory traversal attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of phpWebSite that suffers from
multiple flaws :

  - Multiple SQL Injection Vulnerabilities
    An attacker can affect database queries through the 
    parameters 'module' and 'mod' of the script 'index.php'.
    This may allow for disclosure of sensitive information,
    attacks against the underlying database, and the like.

  - A Directory Traversal Vulnerability
    An attacker can read arbitrary files on the remote host
    by using instances of the substring '../' in the 'mod' 
    parameter of the script 'index.php'.");
  # https://twitter.com/HackersCenter?/HSC-Research-Group/Advisories/HSC-Multiple-vulnerabilities-in-PhpWebSite.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?073827f0");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch referenced in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpwebsite:phpwebsite");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 Tenable Network Security, Inc.");

  script_dependencies("phpwebsite_detect.nasl");
  script_require_keys("www/phpwebsite");
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
install = get_kb_item(string("www/", port, "/phpwebsite"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit one of the SQL injection flaws.
  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/index.php?",
      # nb: this should just produce a SQL syntax error.
      "module=", SCRIPT_NAME, "'&",
      "search_op=search&",
      "mod=all&",
      "query=1&",
      "search=Search" ));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we get a SQL error.
  if (
    egrep(
      string:res, 
      pattern:string("syntax error<.+ FROM mod_search WHERE module='", SCRIPT_NAME)
    )
  ) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
