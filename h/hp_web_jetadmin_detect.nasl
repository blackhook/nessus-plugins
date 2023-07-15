#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44328);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/25");

  script_name(english:"HP Web Jetadmin Detection");
  script_summary(english:"Looks for the Web Jetadmin web root");

  script_set_attribute(attribute:"synopsis", value:"The remote web server contains a printer management application.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running HP Web Jetadmin, a management application
for networked print devices."
  );
  # https://www8.hp.com/us/en/solutions/business-solutions/printingsolutions/wja.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59aaddf1");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:web_jetadmin");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8000);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:8000, embedded:TRUE);

installs = NULL;
banner = get_http_banner(port:port);
if (isnull(banner))
  exit(1, 'Unable to get banner from the web server on port '+port+'.');

headers = parse_http_headers(status_line:banner, headers:banner);
if (isnull(headers))
  exit(1, 'Error processing HTTP response headers from the web server on port '+port+'.');

server = headers['server'];
if (isnull(server))
  exit(0, "The web server on port "+port+" doesn't send a Server response header.");

pattern = '^(HP Web Jetadmin|HP-Web-JetAdmin) *([0-9.]+)?$';
match = eregmatch(string:server, pattern:pattern, icase:TRUE);

if (match)
{
  installs = add_install(
    installs:installs,
    dir:'',
    ver:match[2],
    appname:'hp_web_jetadmin',
    port:port,
    cpe: "cpe:/a:hp:web_jetadmin"
  );

  if (report_verbosity > 0)
  {
    report = get_install_report(
      display_name:'HP Web Jetadmin',
      installs:installs,
      port:port
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else exit(0, "HP Web Jetadmin wasn't detected on port "+port+".");

