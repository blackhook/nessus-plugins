##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(69077);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/09");

  script_name(english:"Cisco Content Security Management Appliance Web Detection");
  script_summary(english:"Checks for the SMA login page.");

  script_set_attribute(attribute:"synopsis", value:
"A web management interface was detected on the remote host.");
  script_set_attribute(attribute:"description", value:
"The web management interface for Cisco Content Security Management
Appliance (SMA) was detected on the remote host. SMA provides
centralized management for Cisco Email Security and Web Security
Appliances.");
  # https://www.cisco.com/c/en/us/products/security/content-security-management-appliance/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e715b383");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:content_security_management_appliance");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"hardware_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('http.inc');
include('webapp_func.inc');

port = get_http_port(default:443, ignore_broken:TRUE);
dir = '';
page = '/login?redirects=10';
url = dir + page;
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

if (
  # new
  (res[2] !~ '<title> *Cisco *Content Security Management' || '/help/sma_help/login.html' >!< res[2]) &&
  # old
  ('<title>Cisco IronPort' >!< res[2] || '/help/index.html?context=SecurityManagementApp_UserGuide' >!< res[2])
)
  audit(AUDIT_WEB_APP_NOT_INST, 'Cisco Content Security Management Appliance', port);

model = NULL;
ver = NULL;

# newer models
match = pregmatch(string:res[2], pattern:'<p class="text_login_model">Cisco ([^<]+)</p>');
if (!isnull(match))
  model = match[1];
match = pregmatch(string:res[2], pattern:'<p class="text_login_version">Version: (\\d+\\.\\d+\\.\\d+-\\d+)</p>');
if (!isnull(match))
  ver = match[1];

# older ironport models
if (isnull(model))
{
  match = pregmatch(string:res[2], pattern:'alt="(Cisco )?IronPort ([^"]+)" class="logo"');
  if (!isnull(match))
    model = match[2];
}
if (isnull(ver))
{
  match = pregmatch(string:res[2], pattern:"v(\d+\.\d+\.\d+-\d+)");
  if (!isnull(match))
    ver = match[1];
}

if (isnull(model))
  model = "Unknown";

if (isnull(ver))
  audit(AUDIT_WEB_APP_NOT_INST, 'Cisco Content Security Management Appliance', port);

set_kb_item(name:'cisco_sma/' + port + '/model', value:model);

# required for compatibility with ccf.inc
set_kb_item(name:'Host/AsyncOS/Cisco Content Security Management Appliance/Version', value:ver);
set_kb_item(name:'Host/AsyncOS/Cisco Content Security Management Appliance/Model', value:model);
set_kb_item(name:'Host/AsyncOS/Cisco Content Security Management Appliance/Port', value:port);

install = add_install(appname:'cisco_sma', dir:dir, port:port, ver:ver, cpe: "cpe:/h:cisco:content_security_management_appliance");

if (report_verbosity > 0)
{
  report = get_install_report(display_name:'Cisco Content Security Management Appliance', installs:install, port:port);
  security_note(port:port, extra:report);
}
else security_note(port);
