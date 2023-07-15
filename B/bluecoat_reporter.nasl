#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(34334);
 script_version("1.10");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");
 script_name(english: "Blue Coat Reporter Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is used to monitor web traffic." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Blue Coat Reporter, a web reporting system
for monitoring centralized logs from Blue Coat appliances.  And this
service is used to access the application." );
 script_set_attribute(attribute:"see_also", value:"https://www.symantec.com" );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/03");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:bluecoat:reporter");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
 script_end_attributes();

 script_summary(english: "Determines if the web server is from Blue Coat Reporter");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english: "Web Servers");
 script_dependencies("http_version.nasl");
 script_require_keys("www/BCReport");
 script_require_ports("Services/www", 8987, 8082);
 exit(0);
}

include("audit.inc");
include("install_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 8082);
version = "N/A";
build = "N/A";

banner = get_http_banner(port: port, exit_on_fail: TRUE);
if ("BCReport/" >!< banner && "Blue Coat Reporter" >!< banner) audit(AUDIT_WEB_APP_NOT_INST, "BlueCoat Reporter", port);

# backup method for version detection
v = eregmatch(string: banner, pattern: '(^|\n)Server:[ \t]*BCReport/([0-9.]+)');
if (isnull(v))
  ver = "N/A";
else
  ver = v[2];

# legacy BC Reporter installs
res = http_send_recv3(
  method    :"GET",
  port      : port,
  item      : "/",
  exit_on_fail: TRUE);

if (isnull(res)) audit(AUDIT_WEB_APP_NOT_INST, "BlueCoat Reporter", port);
page = strcat(res[0], res[1], '\r\n', res[2]);
if ("Blue Coat Reporter" >!< page) audit(AUDIT_WEB_APP_NOT_INST, "BlueCoat Reporter", port);

lines = pgrep(string: page, pattern: "alert");
v = pregmatch(string: lines, pattern: 
'[ \t\r\n]alert[ \t]*\\([ \t]*"Blue Coat Reporter:[ \t]*([0-9.]+).*-[ \t]*build number:[ \t]*([0-9]+).*-[ \t]*UI version:[ \t]*([0-9.R]+)"');

#9.5 BC Reporter installs
if(isnull(v))
{
  res_js = http_send_recv3(method:"GET", port: port, item: "/serverinfo.js", exit_on_fail:TRUE);
  if(!isnull(res_js))
  {
    version = pregmatch(string: res_js[2], pattern:"wr\.version='([0-9]\.[0-9]\.[0-9]\.[0-9])'");
    if(!isnull(version)) version = version[1];
    build = pregmatch(string: res_js[2], pattern:"wr\.build='([0-9]+)'");
    if(!isnull(build)) build = build[1];
    ui_version = version;
  }
}
else # legacy detection worked
{
  version = v[1];
  build = v[2];
  ui_version = v[3];
}

if (! isnull(res_js))
{
register_install(
    vendor          : "BlueCoat",
    product         : "Reporter",
    app_name        : "BlueCoat Reporter",
    path            : '/',
    version         : version,
    display_version : ui_version,
    port            : port,
    cpe             : "cpe:/a:bluecoat:reporter",
    webapp          : TRUE
  );

 report =
'\n  Version      : '+ version +
'\n  Build number : '+ build +
'\n  UI version   : '+ ui_version + '\n';
 set_kb_item(name: "www/"+port+"/BCReport/Version", value: version);
 set_kb_item(name: "www/"+port+"/BCReport/BuildNumber", value: build);
 set_kb_item(name: "www/"+port+"/BCReport/UIVersion", value: ui_version);
}
else
{
 report = '\n  Version : '+ ver + '\n';
 set_kb_item(name: "www/"+port+"/BCReport/Version", value: ver);
}

report_extra = '\nNessus collected the following information from the start page :\n' + report;

security_report_v4(port:port, extra:report_extra, severity:SECURITY_NOTE);
