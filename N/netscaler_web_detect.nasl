# netscaler_web_detect.nasl
# GPLv2
#
# History:
#
# 1.00, 11/21/07
# - Initial release

# Changes by Tenable:
# - Revised plugin title (9/23/09)
# - Added CPE and updated copyright (10/18/2012)

include("compat.inc");

if (description)
{
  script_id(29222);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/31");

  script_xref(name:"IAVT", value:"0001-T-0571");

  script_name(english:"Citrix Application Delivery Controller (ADC) / Citrix NetScaler Detection");
  script_summary(english:"Detects NetScaler web management interface");

  script_set_attribute(attribute:"synopsis", value:
"A Citrix ADC web management interface is running on this port.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be a Citrix ADC (previously NetScaler), an appliance for web
application delivery, and the remote web server is its management
interface.");
  script_set_attribute(attribute:"see_also", value:"https://www.citrix.com/products/citrix-adc/");
  script_set_attribute(attribute:"solution", value:"Filter incoming traffic to this port.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/06");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:netscaler");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:netscaler_application_delivery_controller");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl","httpver.nasl", "broken_web_server.nasl");
  script_require_ports("Services/www", 80, 443);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("install_func.inc");

var app_name = "Citrix ADC / NetScaler";
var cpe = "cpe:/a:citrix:netscaler";
var port=get_http_port(default:80, embedded:TRUE);
var extra;
var failedDetect;
var url = "/";

var resp = http_get_cache_ka(port:port, item:url);

if(empty_or_null(resp))
{
  url = "/index.html";
  resp=http_keepalive_send_recv(port:port,
                              data:http_get(item:url,port:port),
                              embedded:TRUE);
}

if(empty_or_null(resp))
{
  url = "/vpn/index.html";
  resp=http_keepalive_send_recv(port:port,
                              data:http_get(item:url,port:port),
                              embedded:TRUE);
}

if (isnull(resp)) exit(1, "The web server on port "+port+" failed to respond.");

var match1=pgrep(pattern:"<title>(Citrix Login|Citrix Access Gateway)</title>",string:resp,icase:TRUE);
var match2=pgrep(pattern:'action="(/login/do_login|/ws/login\\.pl|/cgi/login)"',string:resp,icase:TRUE);

if (match1 && match2)
{
  replace_kb_item(name:"www/netscaler", value:TRUE);
  replace_kb_item(name:"www/netscaler/"+port, value:TRUE);
  replace_kb_item(name:"www/netscaler/"+port+"/initial_page", value:url);
  replace_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);

  #check for ADC specificially
  if( "<span>Citrix ADC</span>" >< resp)
    extra = {"Product":"Citrix ADC"};
    failedDetect = "The plugin did not attempt to detect the version.";

  register_install(app_name: app_name, 
                    vendor : 'Citrix',
                    product : 'NetScaler Application Delivery Controller',
                    path: url, 
                    port: port, 
                    extra: extra,
                    cpe: cpe, 
                    webapp:TRUE);
}
else
  audit(AUDIT_NOT_DETECT, app_name, port);

report_installs(extra:failedDetect);
