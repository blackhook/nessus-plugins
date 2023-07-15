#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(46224);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/18");

  script_name(english:"TaskFreak! Default Credentials");
  script_summary(english:"Attempts to log in as Admin without a password");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that uses default
credentials.");
  script_set_attribute(attribute:"description", value:
"The installation of TaskFreak! hosted on the remote web server uses the
default username and password to control access to its administrative
console. 

Knowing these, an attacker can gain control of the affected
application.");
  script_set_attribute(attribute:"solution", value:
"Login via the administrative interface and change the password for the
'Admin' account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"score from an analysis done by Tenable");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2010-2023 Tenable Network Security, Inc.");

  script_dependencies("taskfreak_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80);
  script_require_keys("www/taskfreak");

  exit(0);
}

include('http.inc');
include('webapp_func.inc');

var port = get_http_port(default:80, php:TRUE);

var install = get_install_from_kb(appname:'taskfreak', port:port, exit_on_fail:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

var user = 'admin';
var pass = '';
var install_url = build_url(port:port, qs:install['dir']);

var postdata = 'tznUserTimeZone=-14400&username=admin&password=&login=Login';
var req = http_mk_post_req(
  port:port,
  item:install['dir']+'/login.php',
  add_headers:make_array("Content-Type", "application/x-www-form-urlencoded"),
  data:postdata
);
var res = http_send_recv_req(port:port, req:req, follow_redirect:1, exit_on_fail:TRUE);

if (
  '<li>Task' >< res[2] &&
  '<a href="logout.php" title="Logout">' >< res[2] &&
  '<a href="http://www.taskfreak.com">TaskFreak! multi user</a>' >< res[2]
)
{
  var report =
    '\nNessus was able to gain access to the administrative interface using' +
    '\nthe following information :' +
    '\n' +
    '\n  URL      : ' + install_url +
    '\n  User     : ' + user +
    '\n  Password : ' + pass + '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);

  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "TaskFreak", install_url);
