#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10746);
 script_version("1.36");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/22");

  script_xref(name:"IAVT", value:"0001-T-0620");

 script_name(english:"HP System Management Homepage Detection");
 script_summary(english:"Checks for HP System Management Homepage.");

 script_set_attribute(attribute:"synopsis", value:
"A management service is running on the remote web server.");
 script_set_attribute(attribute:"description", value:
"HP System Management Homepage (SMH), formerly Compaq Web Management,
is running on the remote web server. SMH is a web-based application
for managing HP ProLiant and Integrity servers, or HP 9000 and HP
Integrity servers.");
 # http://www8.hp.com/us/en/products/server-software/product-detail.html?oid=344313#!tab%3Dfeatures
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ce81e8f");
 script_set_attribute(attribute:"solution", value:
"It is suggested that access to this service be restricted.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2001/08/29");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:system_management_homepage");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Web Servers");

 script_dependencies("find_service1.nasl", "httpver.nasl");
 script_require_ports("Services/www", 2301, 2381);

 exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("install_func.inc");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:2301);
ports = add_port_in_list(list:ports, port:2381);
port = branch(ports);

if ((empty_or_null(port)) || (!get_port_state(port))) audit(AUDIT_NOT_LISTEN,'HTTP(S)', port);

installs = NULL;

banner = get_http_banner(port:port);
if (empty_or_null(banner)) audit(AUDIT_NO_BANNER, port);

match_banner = pregmatch(pattern:"Server: CompaqHTTPServer/.*?([HPE]{2,3} System Management Homepage)", string:banner);
if(empty_or_null(match_banner)) audit(AUDIT_WRONG_WEB_SERVER, port, 'HP(E) System Management Homepage');
prod =  match_banner[1];

res = http_send_recv3(method:"GET", port:port, item:'/', follow_redirect:3);
if (empty_or_null(res) || '200' >!< res[0]) audit(AUDIT_RESP_BAD, port);

match_version = pregmatch(pattern:'smhversion = "[HPE]{2,3} System Management Homepage v([0-9._]+)".*', string:res[2]);
if(empty_or_null(match_version)) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, prod, port);
version = match_version[1];

installs = add_install(installs:installs, ver:version, appname:'hp_smh', port:port, dir:'', cpe:"cpe:/a:hp:system_management_homepage");
set_kb_item(name:"www/"+port+"/hp_smh/variant", value:prod);
set_kb_item(name:"www/"+port+"/hp_smh/source", value:match_version);
set_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);
set_kb_item(name:"Services/www/hp_smh", value:port);

report = 'The detection came from the following HTML source line:' +
         '\n\n' + match_version[0] + '\n';

report_installs(app_name:'hp_smh', port:port, extra:report);
