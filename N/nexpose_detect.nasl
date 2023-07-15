#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56821);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/22");

  script_name(english:"Nexpose HTTP Server Detection");
  script_summary(english:"Detects a Nexpose HTTP server");

  script_set_attribute(attribute:"synopsis", value:"A Nexpose HTTP server is listening on the remote port.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a Nexpose server, which is used for
performing security scans."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.rapid7.com/products/");
  script_set_attribute(attribute:"solution", value:"Disable this service if you do not use it.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rapid7:nexpose");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2011-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 3780);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:3780);

url = '/login.html';
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

pattern = 'nexposeccusername';
match = eregmatch(string:res[2], pattern:pattern, icase:TRUE);
if (!match) exit(0, "Nexpose wasn't detected on the web server on port " + port + ".");

installs = add_install(
  dir     : '',
  appname : 'nexpose',
  port    : port,
  cpe    : "cpe:/a:rapid7:nexpose"
);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'Nexpose',
    installs     : installs,
    port         : port,
    item         : '/login.html'
  );
  security_note(port:port, extra:report);
}
else security_note(port);
