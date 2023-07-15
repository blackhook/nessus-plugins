#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56565);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2010-4883");
  script_bugtraq_id(43577);

  script_name(english:"MODx < 2.0.3-pl modahsh Parameter XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is vulnerable to a
reflected cross-site scripting attack.");
  script_set_attribute(attribute:"description", value:
"The version of MODx hosted on the remote web server fails to sanitize
the 'modahsh' parameter of the 'manager/index.php' script before using
it to generate dynamic HTML.

By tricking someone into clicking on a specially crafted link, an
attacker may be able exploit this to inject arbitrary HTML and script
code into a user's browser to be executed within the security context
of the affected site.");
  # https://forums.modx.com/thread/226/modx-revolution-2-0-3-out-and-includes-security-fix
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0493e3ff");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MODx to 2.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"d2_elliot_name", value:"MODx Revolution 2.0.2-pl LFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:modxcms:modxcms");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2022 Tenable Network Security, Inc.");

  script_dependencies("modx_detect.nasl");
  script_require_keys("www/PHP", "www/modx");
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

xss = '><script>alert(' + "'" + SCRIPT_NAME + "'" + ');</script>';
res = test_cgi_xss(
  port:port,
  cgi:'/manager/index.php',
  qs:'modahsh="' + xss,
  pass_str:'value=""' + xss,
  ctrl_re:'MODx CMF Manager Login',
  dirs:make_list(dir)
);

if (res == 0)
  exit(0, 'The MODx CMS install at ' + build_url(qs:dir, port:port) + ' is not affected.');
