#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35786);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"Zabbix Web Interface Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a distributed monitoring system written
in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running the web interface for Zabbix, an open
source distributed monitoring system.");
  script_set_attribute(attribute:"see_also", value:"https://www.zabbix.com/");
  script_set_attribute(attribute:"solution", value:
"Make sure the use of this program is in accordance with your
organization's acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zabbix:zabbix");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('webapp_func.inc');
include('http.inc');

var port = get_http_port(default:80, php:TRUE);

# Loop through directories.
var dirs = list_uniq(make_list('/zabbix', cgi_dirs()));

var installs = make_array();
var pre_dir = NULL;
foreach var dir (sort(dirs))
{
  var pre_dir1 = ereg_replace(pattern:"(/[^/]+/).*", string:pre_dir, replace:"\1");
  var new_dir = ereg_replace(pattern:"(/[^/]+/).*", string:dir, replace:"\1");

  if (!isnull(pre_dir1))
    var rpeat = preg(pattern:"^"+pre_dir1+"/", string:new_dir+"/");

  if (rpeat) continue;

  # Request index.php
  var url = dir + '/index.php';
  var res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

  if (
    (
      'href="https://www.zabbix.com/documentation.php" target="_blank">Help' >< res[2] ||
      'href="https://www.zabbix.com/documentation/" target="_blank">Help' >< res[2] ||
      preg(pattern:'href="https://www.zabbix.com/documentation(/[0-9\\.]+/)?">Help', string:res[2], multiline:TRUE)
    ) &&
    (
      preg(pattern:'<form method="post" action="index.php(\\?login=1)?"', string:res[2], multiline:TRUE) ||
      '<form action="index.php" method="post">' >< res[2] ||
      '<form action="index.php">' >< res[2]
    )
  )
  {
    # default to unknown version
    var ver = UNKNOWN_VER;
    if (dir == '') dir = '/';
    pre_dir = dir;

    # get version from API
    # "Starting from Zabbix 2.0.4 the version of the API matches the version of Zabbix."
    var api_version_request = '{"jsonrpc": "2.0","method":"apiinfo.version","params":[],"id":1}';
    var api_res = http_send_recv3(
      method: 'POST',
      item: dir + 'api_jsonrpc.php',
      port: port,
      data: api_version_request,
      add_headers: make_array('Content-Type', 'application/json-rpc'),
      follow_redirect: 1,
      exit_on_fail: TRUE
    );
    var match = pregmatch(pattern:'"result":"([0-9.]+((rc|alpha|beta)[0-9]+)?)"', string:api_res[2]);
    if (!empty_or_null(match) && !empty_or_null(match[1]))
      ver = match[1];

    installs = add_install(
      appname  : 'zabbix',
      installs : installs,
      dir      : dir,
      ver      : ver,
      port     : port,
      cpe     : 'cpe:/a:zabbix:zabbix'
    );
    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if ((max_index(keys(installs)) > 0) && !thorough_tests) break;
  }
}
if (max_index(keys(installs)) == 0) audit(AUDIT_WEB_APP_NOT_INST, 'Zabbix frontend', port);

# Report the findings.
var report = get_install_report(
  display_name : 'Zabbix frontend',
  installs     : installs,
  port         : port
);

security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);