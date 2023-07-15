#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65951);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/22");

  script_xref(name:"IAVT", value:"0001-T-0906");

  script_name(english:"Citrix Access Gateway User Web Interface Detection");
  script_summary(english:"Looks for the Citrix Access Gateway user interface.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web interface for users.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts the web interface for using Citrix Access
Gateway, an SSL VPN appliance.");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/product/ag/v5.0/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:access_gateway");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

app = "Citrix Access Gateway User Web Interface";

# Put together a list of directories we should check for CAG in.
#
# Prioritize the root of the server. This is only necessary because of
# enabling redirects. We need them on to find the logon point, but the
# webapp framework may register a directory that won't work for other
# plugins that depend on this one.
dirs = list_uniq(make_list("", cgi_dirs()));

# Put together checks for different pages that we can confirm the
# name of the software from.
checks = make_nested_array(
  # This will find v4 instances, which have little to identify them.
  "/", make_nested_list(
    make_list(
      '<img +src *= *"/000_header_black_logo.gif"[^>]*>',
      '<img +src *= *"/000_citrixwatermark.gif"[^>]*>'
    ),
    make_list()
  ),

  # This will find v5 instances, which have more to identify them.
  "/lp", make_nested_list(
    make_list(
      '<title> *Citrix +Access +Gateway *</title>',
      '<div +id *= *"AGContentBox"[^>]*>'
    ),
    make_list()
  )
);

# Get the ports that webservers have been found on, defaulting to
# CAG's default HTTPS port for the user interface.
port = get_http_port(default:443);

# Find where CAG is installed.
#
# v5 installs perform multiple redirects, and fail to have anything
# shown if there is no default login point.
installs = find_install(appname:"citrix_access_gateway_user", checks:checks, dirs:dirs, port:port, follow_redirect:3);
if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, app, port);

# Report our findings.
report = get_install_report(
  display_name : app,
  installs     : installs,
  port         : port
);

security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
