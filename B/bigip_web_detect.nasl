##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(30215);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"F5 BIG-IP Web Management Interface Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is a web management interface.");
  script_set_attribute(attribute:"description", value:
"An F5 BIG-IP web management interface is running on this port.");
  script_set_attribute(attribute:"see_also", value:"https://www.f5.com/products/big-ip-services" );
  script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port, possibly using bigpipe command
'httpd allow ....  For regular, non-management network ports, the
traffic can be also restricted with BIG-IP stateful packet filters." );
  script_set_attribute(attribute:"risk_factor", value:"None" );

  script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2008-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www",443);
  exit(0);
}

include('http_func.inc');
include('install_func.inc');

var app = 'F5 BIG-IP web management';
var cpe = 'cpe:/a:f5:big-ip_application_security_manager';
var path = '/tmui/login.jsp';
var extra = NULL;

var port = get_http_port(default:443, embedded:TRUE);

var res = http_get_cache(port:port, item:'/', exit_on_fail:FALSE);

# sanity check root, older versions have BIG-IP in title, while newer versions redirect with Location header
if ( '<title>BIG-IP' >!< res && 'Location: /tmui/login.jsp' >!< res)
{
  # only carry on if res is a 403 with mailto:support@f5.com in the body and the scan is paranoid
  if ( res !~ "HTTP/1\.[0-9]\s+403" || 'mailto:support@f5.com' >!< res)
    audit(AUDIT_WEB_APP_NOT_INST, app, port);
  else if (report_paranoia < 2)
    audit(AUDIT_POTENTIAL_VULN);
  extra = "This install of F5 BIG-IP web management is only reported because 'Report Paranoia' was set to 'Paranoid'.";
}

res = http_get_cache(port:port, item:path, exit_on_fail:FALSE);

if ( res !~ "HTTP/1\.[0-9]\s+403" && ('<title>BIG-IP' >!< res || 'tmui/tmui/login/welcome.jsp' >!< res))
  audit(AUDIT_WEB_APP_NOT_INST, app, port);

# if the root contains BIG-IP in the title and /tmui/login.jsp returns a 403 with mailto:support@f5.com in the body
# then we still consider this to be a BIG-IP webserver
if (res =~ "HTTP/1\.[0-9]\s+403" && 'mailto:support@f5.com' >!< res)
  audit(AUDIT_WEB_APP_NOT_INST, app, port);

replace_kb_item(name:'www/bigip', value:TRUE);
replace_kb_item(name:'www/'+port+'/bigip', value:TRUE);
replace_kb_item(name:'Services/www/'+port+'/embedded', value:TRUE);

register_install(
  vendor: "F5",
  product: "BIG-IP Application Security Manager",
  app_name: app,
  port: port,
  version: UNKNOWN_VER,
  path: path,
  webapp: TRUE,
  cpe: cpe
);

report_installs(app_name:app, extra: extra);