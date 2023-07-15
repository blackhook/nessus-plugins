#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106628);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"lighttpd HTTP Server Detection");
  script_summary(english:"Detects the lighttpd HTTP server");

  script_set_attribute(attribute:"synopsis", value:
"The lighttpd HTTP server was detected on the remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to detect the lighttpd HTTP server by looking at
the HTTP banner on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://www.lighttpd.net/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lighttpd:lighttpd");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/lighttpd");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

get_kb_item_or_exit("www/lighttpd");

appname = 'lighttpd';
port = get_http_port(default:80);
banner = get_http_banner(port:port, exit_on_fail:TRUE);

# Server: lighttpd
# Server: lighttpd/1.4.39
# Server: LightTPD/1.4.19 (Win32)
# Server: lighttpd/1.4.35-devel-183425
# Server: LightTPD/1.4.39-1-IPv6 (Win32)
matches = pregmatch(pattern:"Server: lighttpd/?([0-9\.]+)?[0-9a-zA-Z-]*? ?(?:\(([a-zA-Z-0-9]+)\))?[\r\n]", string:banner, icase:TRUE);
if (empty_or_null(matches))
{
  audit(AUDIT_WRONG_WEB_SERVER, port, appname);
}

version = NULL;
extra_array = make_array("source", matches[0]);

if (!empty_or_null(matches[1]))
{
  version = matches[1];
  if (!empty_or_null(matches[2]))
  {
    extra_array["os"] = matches[2];
  }
}

register_install(
    vendor:"Lighthttpd",
    product:"Lighthttpd",
    app_name:appname,
    path:'/',
    version:version,
    port:port,
    extra:extra_array,
    webapp:TRUE,
    cpe: "cpe:/a:lighttpd:lighttpd");

report_installs(app_name:appname, port:port);
