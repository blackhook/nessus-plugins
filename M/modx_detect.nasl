#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46182);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"MODx CMS Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an open source content management system
written in PHP");
  script_set_attribute(attribute:"description", value:
"The remote host is running MODx, an open source content management
system written in PHP.");
  script_set_attribute(attribute:"see_also", value:"https://modx.com/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:modxcms:modxcms");
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

dirs = cgi_dirs();
if (thorough_tests)
{
  dirs = list_uniq(make_list(dirs, '/modx'));
}

installs = NULL;
foreach dir (dirs)
{
  url = dir + '/manager/';
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if (
    (res[2] =~ "<title>MODx CMF Manager Login</title>" &&
    res[2] =~ 'Please enter your login credentials to start your Manager session.') ||

    (res[2] =~ "Login \| MODX Revolution</title>" &&
    res[2] =~ 'modx-login-username')
  )
  {
    installs = add_install(
      installs:installs,
      dir:dir,
      appname:'modx',
      port:port,
      cpe: "cpe:/a:modxcms:modxcms"
    );

    if (!thorough_tests) break;
  }
}

if (isnull(installs)) exit(0, "MODx wasn't detected on port "+port+".");

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'MODx',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
