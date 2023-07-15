#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(58592);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"Apache Traffic Server Version");
  script_summary(english:"Obtains the version of the remote Apache Traffic Server.");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the version number of the remote Apache
Traffic Server.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Apache Traffic Server, an open source
caching server. It was possible to read the version number from the
banner.");
  script_set_attribute(attribute:"see_also", value:"http://trafficserver.apache.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:traffic_server");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/apache_traffic_server");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include('http.inc');
include('install_func.inc');

var appname = 'Apache Traffic Server';
var port = get_http_port(default:8080);
var server_header = http_server_header(port:port);

if (isnull(server_header)) 
  audit(AUDIT_WEB_NO_SERVER_HEADER, port);

if ('ATS/' >!< server_header) 
  audit(AUDIT_WRONG_WEB_SERVER, port, appname);

var extra_array = make_array();
var ver = NULL;
var ver_pat = "^ATS\/([0-9\.]+)";

var match = pregmatch(pattern:ver_pat, string:server_header);

if(!empty_or_null(match))
{
  if (match[1]) 
    ver = match[1];
}

else 
  ver = 'Unknown';

extra_array['Version Source'] = 'Server: ' + match[0];

register_install(
    vendor:"Apache",
    product:"Traffic Server",
    app_name:appname,
    path:'/',
    version:ver,
    port:port,
    extra:extra_array,
    webapp:TRUE,
    cpe: "cpe:/a:apache:traffic_server");

report_installs(app_name:appname, port:port);