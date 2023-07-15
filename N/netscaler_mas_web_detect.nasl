#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');
if (description)
{
  script_id(118087);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"Citrix NetScaler Application Delivery Management (ADM)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host appears to be running Citrix NetScaler Application Delivery Management (ADM), formerly know as
Management and Analytics System (MAS).");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running Citrix NetScaler Application Delivery Management (ADM), formerly know as 
Management and Analytics System (MAS). ADM provides centralized network management, analytics, automation, and
orchestration to support applications deployed across hybrid cloud and containerized infrastructures. From a single 
platform, admins can view, automate, and manage network services across their entire infrastructure.");
  script_set_attribute(attribute:"see_also", value:"https://www.citrix.com/products/citrix-application-delivery-management/");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a8a1c18a");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:netscaler");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:netscaler:application_delivery_management");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl", "httpver.nasl", "broken_web_server.nasl");
  script_require_ports("Services/www", 80, 443);
  exit(0);
}

include('http.inc');
include('install_func.inc');

port = get_http_port(default:80);
# Keeping MAS appname for backward compatability
appname = 'NetScaler Management and Analytics System';
not_installed = 'NetScaler Application Delivery Management / Management and Analytics System';
dir = '/admin_ui/mas/ent/login.html';

if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

res = http_send_recv3(
  method:'GET',
  item:dir,
  port:port,
  exit_on_fail:TRUE
);

if (empty_or_null(res[2])) 
{
  audit(AUDIT_WEB_APP_NOT_INST, not_installed, port);
}

if (
  # As MAS is now ADM, need to check for both in HTML <title>
  ("<title>NetScaler Management and Analytics System</title>" >< res[2] ||
  "<title>Application Delivery Management</title>" >< res[2]) &&
  "/admin_ui/mas/ent/html/main.html" >< res[2]
) 
{
  register_install(
    vendor:"NetScaler",
    product:"Application Delivery Management",
    app_name: appname,
    path: dir,
    port: port,
    webapp: TRUE,
    cpe: "cpe:/a:citrix:netscaler:application_delivery_management"
  );
  report_installs(app_name: appname, port:port);  
}

else
{
  audit(AUDIT_WEB_APP_NOT_INST, not_installed, port);
}
