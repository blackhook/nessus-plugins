#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51674);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"ExtCalendar Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a calendar system written in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running ExtCalendar, a web-based calendar system
written in PHP.

Note that Nessus has detected the standalone version of ExtCalendar,
not the component version often embedded into other web applications.");
  script_set_attribute(attribute:"see_also", value:"https://sourceforge.net/projects/extcal/");
  script_set_attribute(attribute:"solution", value:
"Consider switching to another application as ExtCalendar is no longer
actively maintained and affected by at least one vulnerability.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:extcalendar:extcalendar");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

ver_comment_pat  = "<!--ExtCalendar ([0-9.]+.*)-->";

dirs        = cgi_dirs();
if (thorough_tests)
{
  dirs = make_list(dirs, '/calendar', '/extcal', '/extcalendar');
  dirs = list_uniq(dirs);
}

installs    = NULL;
foreach dir (dirs)
{
  extcal  = FALSE;
  ver     = NULL;

  url     = dir + '/login.php';
  res = http_send_recv3(method: "GET", item: url, follow_redirect: 5, port: port, exit_on_fail: TRUE);

  # check for version 2x
  if ('Powered by <a href="http://extcal.sourceforge.net/" target="_new">ExtCalendar' >< res[2])
  {
    extcal  = TRUE;
    matches = eregmatch(pattern:ver_comment_pat , string:res[2], icase:FALSE);
    if (!isnull(matches)) ver = matches[1];
  }
  else
  {
    # check another url for another version
    url = dir + '/admin/cal_login.php';
    res = http_send_recv3(method: "GET", item: url, follow_redirect: 5, port: port, exit_on_fail: TRUE);

    if (
      '<head><title>Extcalendar login</title></head>'  >< res[2] &&
      '<form action=cal_login.php?op=login method=post>' >< res[2]
    ) extcal = TRUE;
  }

  if (extcal)
  {
    installs = add_install(
      installs : installs,
      dir      : dir,
      appname  : 'extcalendar',
      ver      : ver,
      port     : port,
      cpe     : "cpe:/a:extcalendar:extcalendar"
    );
    if (!thorough_tests) break;
  }
}

if (isnull(installs)) exit(0, "ExtCalendar wasn't detected on port "+port+".");

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'ExtCalendar',
    installs     : installs,
    port         : port
  );
  security_note(port: port, extra: report);
}
else security_note(port);
