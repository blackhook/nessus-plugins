#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(46223);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"TaskFreak! Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an open source task management
application written in PHP");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts TaskFreak!, an open source task
management application written in PHP.");
  script_set_attribute(attribute:"see_also", value:"http://www.taskfreak.com/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:taskfreak:taskfreak");
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
  dirs = list_uniq(make_list(dirs, '/taskfreak'));
}

installs = NULL;
foreach dir (dirs)
{
  url = dir + '/login.php';
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if (
    '<title>TaskFreak!</title>' >< res[2] &&
    '<a href="http://www.taskfreak.com">TaskFreak! multi user</a>' >< res[2]
  )
  {
    version  = NULL;
    pat = '<a href="http://www.taskfreak.com">TaskFreak! multi user</a> v([0-9\\.]+)';
    matches = egrep(pattern:pat, string:res[2]);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          version = item[1];
          break;
        }
      }
    }

    if (isnull(version)) version = 'unknown';

    installs = add_install(
      installs:installs,
      ver:version,
      dir:dir,
      appname:'taskfreak',
      port:port,
      cpe: "cpe:/a:taskfreak:taskfreak"
    );

    if (!thorough_tests) break;
  }
}

if (isnull(installs)) exit(0, "TaskFreak! wasn't detected on port "+port+".");

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'TaskFreak!',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port:port);
