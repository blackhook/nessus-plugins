#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46236);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"Campsite Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web publishing application written in
PHP.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts Campsite, an open source web publishing
application written in PHP.");
  script_set_attribute(attribute:"see_also", value:"http://www.campware.org/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:campware.org:campsite");
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
  dirs = list_uniq(make_list(dirs, '/campsite'));
}

installs = NULL;
foreach dir (dirs)
{
  url = dir + '/admin/login.php';
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if (
    '<title>Campsite' >< res[2] &&
    'Please enter your user name and password' >< res[2] &&
    '&copy; Campware - MDLF' >< res[2]
  )
  {
    version = NULL;
    pat = 'Campsite&nbsp;([0-9\\.]+).*Copyright &copy; Campware';
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

    installs = add_install(
      installs:installs,
      ver:version,
      dir:dir,
      appname:'campsite',
      port:port,
      cpe: "x-cpe:/a:campware.org:campsite"
    );

    if (!thorough_tests) break;
  }
}

if (isnull(installs)) exit(0, "Campsite wasn't detected on port "+port+".");

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'Campsite',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
