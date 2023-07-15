#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67246);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_xref(name:"IAVT", value:"0001-T-0556");

  script_name(english:"Cisco Prime Data Center Network Manager Web Detection");
  script_summary(english:"Looks for the dcnm login page.");

  script_set_attribute(attribute:"synopsis", value:
"The web interface for a network management system was detected on the
remote host.");
  script_set_attribute(attribute:"description", value:
"The web interface for Cisco Prime Data Center Network Manager (DCNM)
was detected on the remote host. DCNM is used to manage virtualized
data centers.");
  # https://www.cisco.com/c/en/us/products/cloud-systems-management/prime-data-center-network-manager/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?946c0157");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_data_center_network_manager");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");
include("json.inc");

port = get_http_port(default:80);
dir = '';
page = '/';
url = dir + page;
found = FALSE;
ver = NULL;
appname = "Cisco Prime DCNM";

res = http_get_cache(item:url, port:port, exit_on_fail:TRUE);
if ('<title>Data Center Network Manager</title>' >< res)
{
  if(res =~ '<div class="productName" *>Data Center Network Manager</div>')
  {
    match = pregmatch(string:res, pattern:'productVersion">Version:? ([^<]+)<');
    if (!isnull(match))
    {
      ver = match[1]; # e.g., 6.1(1b)
      found = TRUE;
    }
  }
  else if("/fm/fmrest/about/version" >< res)
  {
    res = http_send_recv3(method:"GET", item:"/fm/fmrest/about/version", port:port);
    if(!isnull(res[2])) data = json_read(res[2]);
    ver = data[0].version;
    found = TRUE;
  }
}

if(!found) audit(AUDIT_WEB_APP_NOT_INST, appname, port);

# install_func.inc
register_install(
  app_name        : 'cisco_dcnm_web',
  vendor : 'Cisco',
  product : 'Prime Data Center Network Manager',
  path            : dir,
  version         : ver,
  port            : port,
  cpe             : "cpe:/a:cisco:prime_data_center_network_manager",
  webapp          : TRUE
);

report_installs(port:port);
