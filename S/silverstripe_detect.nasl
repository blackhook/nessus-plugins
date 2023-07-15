#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44331);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"SilverStripe CMS Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server host a PHP-based content management system.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts SilverStripe CMS, an open source content
management system (CMS) application written in PHP.");
  script_set_attribute(attribute:"see_also", value:"https://www.silverstripe.org/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:silverstripe:silverstripe");
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

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The remote web server on port "+port+" does not support PHP.");

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/silverstripe", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  res = http_send_recv3(method:"GET", item:dir+"/Security/login", port:port);
  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");
  if (
    ('<meta name="generator" http-equiv="generator" content="SilverStripe - http://www.silverstripe.com" />' >< res[2] ||   # <= 2.3.x
     '<meta name="generator" content="SilverStripe - http://silverstripe.org" />' >< res[2]) &&  # >= 2.4.x
    'This site runs on the SilverStripe CMS">SilverStripe Open Source CMS' >< res[2]
  )
  {
    # Try to get the version if possible
    url = dir + '/cms/silverstripe_version';
    res = http_send_recv3(method:'GET', item:url, port:port);

    match = eregmatch(string:res[2], pattern:'/cms/tags/(alpha/|beta/|rc/)?([^/]+)/silverstripe_version');
    if (isnull(match)) ver = NULL;
    else ver = match[2];

    installs = add_install(
      appname:'silverstripe',
      dir:dir,
      ver:ver,
      port:port,
      installs:installs,
      cpe: "cpe:/a:silverstripe:silverstripe"
    );
  }
  if (!isnull(installs) && !thorough_tests) break;
}

if (isnull(installs))
  exit(0, "SilverStripe CMS was not detected on port "+port+".");

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'SilverStripe',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
