#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(67173);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"php-Charts Detection");

  script_set_attribute(attribute:"synopsis", value:
"A chart creation application is hosted on the remote web server.");
  script_set_attribute(attribute:"description", value:
"php-Charts, a PHP application for creating chart images on a web
server, is hosted on the remote web server.");
  script_set_attribute(attribute:"see_also", value:"http://www.php-charts.com/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:php_charts:php_charts");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
required_strings = make_list(
 '<title>Wizard</title>',
 'name="wizard_frm" enctype="multipart/form-data" onsubmit="return checkFields();" >',
 "<select name='type' onchange='changeChart()' ><option selected value='bar' >bar</option><option value='pie' >pie</option><option value='pie_explode' >pie_explode</option>"
);

if (thorough_tests) dirs = list_uniq(make_list("/php-charts", "/charts", "/php-charts_v1.0", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  installed = FALSE;
  url = dir + '/wizard/index.php';
  res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

  foreach item (required_strings)
  {
    if (item >< res[2]) installed = TRUE;
    else
    {
      installed = FALSE;
      break;
    }
  }

  if (installed)
  {
    installs = add_install(
      installs:installs,
      dir     : dir,
      ver     : 'unknown',    # Cannot currently get a version number
      appname : 'php-charts',
      port    : port,
      cpe    : "x-cpe:/a:php_charts:php_charts"
    );

    if (!thorough_tests) break;
  }
}

if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, "php-Charts", port);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'php-Charts',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
