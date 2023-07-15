#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62122);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"LogAnalyzer Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a monitoring application.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts Adiscon LogAnalyzer, a monitoring
application used to view Syslog messages and Windows Events via a web
interface written in PHP.");
  script_set_attribute(attribute:"see_also", value:"http://loganalyzer.adiscon.com/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adiscon:loganalyzer");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

appname = "Adiscon LogAnalyzer";
port = get_http_port(default:80, php:TRUE);

if (thorough_tests) dirs = list_uniq(make_list("/loganalyzer", "/log", cgi_dirs()));
else dirs = make_list(cgi_dirs());

checks = make_array();
regexes = make_list();
regexes[0] = make_list('target="_blank">Adiscon LogAnalyzer');
regexes[1] = make_list("Adiscon LogAnalyzer</A>\s*Version ([0-9.]+)");
checks["/index.php"] = regexes;
installs = find_install(appname:appname, checks:checks, dirs:dirs, port:port);
if(isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, appname, port);
report_installs(app_name:appname, port:port);
