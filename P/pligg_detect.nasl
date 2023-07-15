#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(47765);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"Pligg Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a content management system written
in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Pligg, a web-based content management
system written in PHP.");
  script_set_attribute(attribute:"see_also", value:"http://www.pligg.com");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pligg:pligg_cms");
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

port = get_http_port(default:80, php: TRUE);

installs = NULL;
meta_tag = '<meta name="description" content="Pligg is an open source content management system that lets you easily <a href=\'http://www.pligg.com\'>create your own social network</a>." />';
dirs     = cgi_dirs();

if (thorough_tests)
{
  dirs = make_list(dirs, '/pligg');
  dirs = list_uniq(dirs);
}

foreach dir (dirs)
{
  url = string(dir, '/');
  res = http_send_recv3(method: "GET", item: url, port: port, exit_on_fail: TRUE);

  if (meta_tag >< res[2])
  {
    installs = add_install(
      installs : installs,
      dir      : dir,
      appname  : 'pligg',
      port     : port,
      cpe     : "cpe:/a:pligg:pligg_cms"
    );

    if (!thorough_tests) break;
  }
}

if (isnull(installs)) exit(0, "Pligg wasn't detected on port "+port+".");

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'Pligg',
    installs     : installs,
    port         : port
  );
  security_note(port: port, extra: report);
}
else security_note(port);
