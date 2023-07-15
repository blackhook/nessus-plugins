#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(117616);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"Apache Hadoop YARN ResourceManager Web Interface");
  script_summary(english:"Looks for the ResourceManager status page");

  script_set_attribute(attribute:"synopsis", value:
"The web interface for a distributed computing system was detected on
the remote host.");
  script_set_attribute(attribute:"description", value:
"The web interface for Hadoop YARN ResourceManager was detected on the
remote host.  This interface can be used to monitor and assign
resources for application execution.");
  script_set_attribute(attribute:"see_also", value:"http://hadoop.apache.org/");
  script_set_attribute(attribute:"solution", value:"Limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:hadoop");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8088);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:8088);
banner = get_http_banner(port:port);
app = "YARN ResourceManager";

if (!banner || '/cluster' >!< banner)
  audit(AUDIT_NOT_INST, app);

res = http_send_recv3(method:'GET', item:'/cluster/cluster', port:port, exit_on_fail:TRUE);

match = pregmatch(string:res[2], pattern:"ResourceManager version:\s+(?:</th>\s+)?<td>\s+([0-9\.]+)", icase:TRUE);
if (!match || !match[1])
  audit(AUDIT_UNKNOWN_APP_VER, app);

register_install(
  vendor:"Apache",
  product:"Hadoop",
  app_name:app,
  path:'/',
  version:match[1],
  port:port,
  webapp:TRUE,
  cpe: "cpe:/a:apache:hadoop"
);

report_installs(app_name:app, port:port);
