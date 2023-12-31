#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43863);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"OpenX Source Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running an ad server written in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running OpenX Source (previously known as Openads),
an open source ad server.");
  script_set_attribute(attribute:"see_also", value:"http://www.openx.org/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openx:openx_source");
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
app = "OpenX Source";
installs = NULL;
pattern = '<meta name=[\'"]generator[\'"] content=[\'"]Open(X|ads) v([0-9\\.]+) ';

dirs = cgi_dirs();

if (thorough_tests)
{
  dirs = make_list(dirs, '/openx', '/openads', '/ads', '/adserver');
  dirs = list_uniq(dirs);
}

foreach dir (dirs)
{
  url = dir + '/www/admin/index.php';
  res = http_send_recv3(
    method : "GET",
    item   : dir + "/",
    port   : port,
    exit_on_fail : TRUE,
    follow_redirect : 2
);

  match = eregmatch(string:res[2], pattern:pattern, icase:TRUE);
  if (match)
  {
    installs = add_install(
      installs:installs,
      dir:dir,
      ver:match[2],
      appname:'openx',
      port:port,
      cpe: "cpe:/a:openx:openx_source"
    );

    if (!thorough_tests) break;
  }
}

if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, app, port);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:app,
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
