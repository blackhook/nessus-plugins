#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69080);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/20");

  script_name(english:"Cisco Web Security Appliance Web Detection");
  script_summary(english:"Looks for the WSA login page.");

  script_set_attribute(attribute:"synopsis", value:
"A web management interface was detected on the remote host.");
  script_set_attribute(attribute:"description", value:
"The web management interface for a Cisco Web Security Appliance (WSA)
was detected on the remote host.");
  # https://www.cisco.com/c/en/us/products/security/web-security-appliance/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd41b0ab");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"hardware_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8443);

  exit(0);
}

include("http.inc");
include("webapp_func.inc");

var port = get_http_port(default:8443);
var dir = '';
var page = '/login?redirects=10';
var url = dir + page;
var res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);
var control = 0;

dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:'Response:\nSTATUS:\n' + res[0] + '\nHEADERS:\n' + res[1] + '\nBODY:\n' + res[2] + '\n');

# Older versions
if ('<title>Cisco IronPort' >< res[2])
  control += 1;

# Newer versions
if (res[2] =~ "<title>\s+Cisco\s+Web Security Virtual Appliance")
  control += 1;

# All versions, apparently
if ('/help/wsa_help/login.html' >< res[2])
  control += 1;
else
  control -= 1;

if (control <= 0)
  audit(AUDIT_WEB_APP_NOT_INST, 'Cisco Web Security Appliance', port);

# Older versions
var model = FALSE;
var match = pregmatch(string:res[2], pattern:'alt="(Cisco )?IronPort ([^"]+)" class="logo"');
if (!isnull(match))
  model = match[2];

# Newer versions
if (!model)
{
  match = pregmatch(string:res[2], pattern:'text_login_model">(Cisco )?([A-Za-z0-9]+)</p');
  if (!isnull(match))
    model = match[2];
}

if (model)
  set_kb_item(name:'cisco_wsa/' + port + '/model', value:match[2]);

match = pregmatch(string:res[2], pattern:"([Vv]ersion: )([0-9.-]+)(?: for Web)?");
if (isnull(match))
  var ver = NULL;
else
  ver = match[2];

var install = add_install(appname:'cisco_wsa', dir:dir, port:port, ver:ver, cpe: "cpe:/h:cisco:web_security_appliance");

if (report_verbosity > 0)
{
  var report = get_install_report(display_name:'Cisco Web Security Appliance', installs:install, port:port);
  security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
}
else
  security_report_v4(port:port, severity:SECURITY_NOTE);
