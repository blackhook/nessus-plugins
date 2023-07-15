#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55719);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/25");

  script_name(english:"Computer Associates ARCserve D2D Detection");
  script_summary(english:"Checks for ARCserve D2D initial page");

  script_set_attribute(attribute:"synopsis", value:"The remote web server hosts a backup application.");
  script_set_attribute(
    attribute:"description",
    value:

"The remote web server is part of ARCserve D2D, a disk-based backup
product from Computer Associates.

"
  );
  script_set_attribute(attribute:"see_also", value:"http://arcserve.com/us/Products/CA-ARCserve-D2D.aspx");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:arcserve_d2d");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8014);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:8014, embedded:FALSE);


url = '/';
res = http_get_cache(item:url, port:port, exit_on_fail:TRUE);

if (
  'CA ARCserve D2D needs JavaScript' >< res &&
  '<meta name="gwt:property"' >< res
)
{
  # nb: there doesn't seem to be a way to get the version remotely
  #     without credentials.
  version = NULL;

  installs = add_install(
    appname  : "arcserve_d2d",
    installs : installs,
    port     : port,
    dir      : "",
    ver      : version,
    cpe      : "cpe:/a:ca:arcserve_d2d"
  );
}
if (isnull(installs))
  exit(0, "ARCserve D2D was not detected on the web server on port "+port+".");


# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    item         : url,
    display_name : "ARCserve D2D"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
