#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(44392);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"OCS Inventory NG Server Administration Console Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting an asset management application
written in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote web server is hosting the OCS Inventory NG Server
Administration console, a PHP application for managing computing
assets.");
  script_set_attribute(attribute:"see_also", value:"https://www.ocsinventory-ng.org/en/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ocsinventory-ng:ocs_inventory_ng");
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
include("webapp_func.inc");
include("http.inc");

port = get_http_port(default:80, php: 1);


if (thorough_tests) dirs = list_uniq(make_list("/ocsreports", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  res = http_get_cache(port:port, item:dir+"/index.php", exit_on_fail: 1);
  if (
    '<TITLE>OCS Inventory</TITLE>' >< res &&
    '<LINK REL=\'StyleSheet\' TYPE=\'text/css\' HREF=\'css/ocsreports.css\'>' >< res &&
    '<td><b>User:</b></td>' >< res &&
    '<td><b>Password:</b></td>' >< res
  )
  {
    match = eregmatch(string:res, pattern:"<b>Ver\. ([0-9\.]+)&nbsp&nbsp&nbsp;</b>");
    if (match) version = match[1];
    else version = 'unknown';

    installs = add_install(
      installs:installs,
      dir:dir,
      ver:version,
      appname:'ocs_inventory',
      port:port,
      cpe: "cpe:/a:ocsinventory-ng:ocs_inventory_ng"
    );

    if (!thorough_tests) break;
  }
}
if (isnull(installs)) exit(0, "OCS Inventory NG wasn't detected on port "+port+".");

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'OCS Inventory NG Server Administration Console',
    item:"/index.php",
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
