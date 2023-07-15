#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44382);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"MoinMoin Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a wiki written in Python.");
  script_set_attribute(attribute:"description", value:
"The remote host is running MoinMoin, a wiki written in Python.");
  script_set_attribute(attribute:"see_also", value:"http://www.moinmo.in/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:moinmo:moinmoin");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
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

dirs = cgi_dirs();
if (thorough_tests)
{
  dirs = make_list(dirs, '/wiki', '/moin.cgi', '/moinmoin');
  dirs = list_uniq(dirs);
}

checks = make_array();

regexes = make_list();
regexes[0] = make_list("MoinMoin(<\/a>)? Version<");
regexes[1] = make_list("<dd>Release (.+) \[Revision");
checks["/SystemInfo"] = regexes;

installs = find_install(
  appname : "moinmoin",
  checks  : checks,
  dirs    : dirs,
  port    : port
);
if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, "MoinMoin", port);

report = NULL;
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : "MoinMoin",
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);

