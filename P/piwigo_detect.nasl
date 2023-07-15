#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65768);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"Piwigo Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a photo gallery written in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts Piwigo, an open source photo gallery
application written in PHP.");
  script_set_attribute(attribute:"see_also", value:"http://piwigo.org/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:piwigo:piwigo");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (thorough_tests) dirs = list_uniq(make_list("/piwigo", "/gallery", "/photos", cgi_dirs()));
else dirs = make_list(cgi_dirs());

checks = make_array();

regexes = make_list();
regexes[0] = make_list(
  '\\<a href="http://piwigo\\.org" class="Piwigo"\\>|<title>Piwigo',
  'content="Piwigo|browse your empty gallery\\</a\\>',
  'type="submit" name="login"'
);

checks["/index.php"] = regexes;

installs = find_install(
  appname : "piwigo",
  checks  : checks,
  dirs    : dirs,
  port    : port
);

if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, "Piwigo", port);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'Piwigo',
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);

