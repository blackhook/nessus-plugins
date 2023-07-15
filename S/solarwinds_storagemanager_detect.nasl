#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59115);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/22");

  script_name(english:"SolarWinds Storage Manager Detection");
  script_summary(english:"Detects installs of SolarWinds Storage Manager");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is running a web-based storage management application."
  );
  script_set_attribute(
    attribute:"description",
    value:
"SolarWinds Storage Manager was detected on the remote host. 
SolarWinds Storage Manager is a web-based storage management
application."
  );
  # https://www.solarwinds.com/storage-resource-monitor
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ef92520");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:storage_manager");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 9000);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

appname = "SolarWinds Storage Manager";
port = get_http_port(default:9000);

installs = NULL;
url = '/';

res = http_get_cache(item:url, port:port, exit_on_fail:TRUE);

if (
  "<title>SolarWinds - Storage Manager</title>" >< res &&
  "LoginServlet" >< res
)
{
  version = "unknown";
  installs = add_install(
    appname  : "solarwinds_storage_manager",
    installs : installs,
    port     : port,
    dir      : "",
    ver      : version,
    cpe      : "cpe:/a:solarwinds:storage_manager"
  );
}

if (isnull(installs))
  audit(AUDIT_NOT_DETECT, appname, port);

if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    item         : url,
    display_name : appname
  );
  security_note(port:port, extra:report);
}
else security_note(port);
