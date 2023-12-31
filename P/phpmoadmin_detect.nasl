#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84216);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"phpMoAdmin Detection");

  script_set_attribute(attribute:"synopsis", value:
"A MongoDB management application is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote web server is hosting phpMoAdmin, a web application for
managing MongoDB instances.");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmoadmin.com/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:avinu:phpmoadmin");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'phpMoAdmin';
port = get_http_port(default:80);

exists = FALSE;
page = '/moadmin.php';

if (thorough_tests) dirs = list_uniq(make_list('', '/moadmin', cgi_dirs()));
else dirs = make_list('', '/moadmin');

foreach dir (dirs)
{
  url = dir + page;
  res = NULL;
  res = http_send_recv3(method:"GET", item:url, port:port, fetch404:TRUE, exit_on_fail:TRUE);

  if ("<title>phpMoAdmin</title>" >!< res[2])
    continue;

  url = url + "?action=getStats";
  res = NULL;
  res = http_send_recv3(method:"GET", item:url, port:port, fetch404:TRUE, exit_on_fail:TRUE);

  version = UNKNOWN_VER;
  match = eregmatch(string:res[2], pattern:"phpMoAdmin: ?([0-9]+\.[0-9]+\.[0-9]+)");
  if (!isnull(match) && !empty_or_null(match[1]))
    version = match[1];

  register_install(
    vendor   : "Avinu",
    product  : "phpMoAdmin",
    app_name : app,
    path     : url,
    version  : version,
    port     : port,
    webapp   : TRUE,
    cpe   : "cpe:/a:avinu:phpmoadmin"
  );

  exists = TRUE;
  if (!thorough_tests) break;
}

if (!exists) audit(AUDIT_WEB_APP_NOT_INST, app, port);
else report_installs(port:port);
