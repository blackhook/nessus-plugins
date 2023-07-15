#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63078);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"Piwik Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a web analytics tool.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running Piwik, a web analytics tool used for
detailed reporting of website analytics.");
  script_set_attribute(attribute:"see_also", value:"https://matomo.org/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:piwik:piwik");
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

appname = "Piwik";

port = get_http_port(default:80, php:TRUE);

if (thorough_tests) dirs = list_uniq(
    make_list("/analytics/piwik", "/piwik", cgi_dirs())
);
else dirs = make_list(cgi_dirs());
checks = make_array();

regexes = make_list();

# check the changelog for the version
regexes[0] = make_list('# Piwik Platform Changelog');
regexes[1] = make_list('## Piwik ([0-9.]+-*[a-z0-9]*)'); #get version
checks["/CHANGELOG.md"] = regexes;

regexes[0] = make_list(
    '(<title>Piwik &rsaquo; Sign in)|(<title>Sign in - Piwik)',
    'a href="http://piwik.org"'
);
# version unknown
checks["/index.php"] = regexes;

installs = find_install(
    appname : appname,
    checks : checks,
    dirs : dirs,
    port : port,
    cpe : 'cpe:/a:piwik:piwik'
);

if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, appname, port);

report_installs(port:port);
