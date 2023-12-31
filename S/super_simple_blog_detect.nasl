#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


include('deprecated_nasl_level.inc');
include("compat.inc");


if (description)
{
  script_id(50047);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Super Simple Blog Script Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a blogging application in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Super Simple Blog Script, a web-based
blogging application written in PHP.");
  script_set_attribute(attribute:"see_also", value:"https://supersimple.org/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:supersimple:super_simple_blog_script");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
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

installs = NULL;
comment_str  = '<!--\nsuper simple PHP blog\n\n' +
  'written by Todd Resudek for ' +
  'TR1design.net.\ntodd@tr1design.net\n\n' +
  'source available at http://www.supersimple.org';

dirs = cgi_dirs();
if (thorough_tests)
{
  dirs = make_list('/ssb', '/supersimpleblog', '/blog', dirs);
  dirs = list_uniq(dirs);
}

foreach dir (dirs)
{
  url = dir + '/index.php';
  res = http_get_cache(item:url, port: port, exit_on_fail: 1);

  if (comment_str >< res)
  {
    installs = add_install(
      installs : installs,
      dir      : dir,
      appname  : 'super_simple_blog',
      port     : port,
      cpe     : "cpe:/a:supersimple:super_simple_blog_script"
    );
  }
  if (!thorough_tests) break;
}

if (isnull(installs)) exit(0, "Super Simple Blog Script wasn't found on port "+port+".");

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'Super Simple Blog Script',
    installs     : installs,
    port         : port
  );
  security_note(port: port, extra: report);
}
else security_note(port);
