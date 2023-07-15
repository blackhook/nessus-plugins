#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107197);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/16");

  script_name(english:"Quest DR Series Appliance Web Default Administrator Credentials");
  script_summary(english:"Attempts to login with default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"A web application is protected using default administrative
credentials.");
  script_set_attribute(attribute:"description", value:
"The web interface for the Quest DR Series disk backup appliance,
formerly Dell DR Series, uses a default set of credentials
(administrator / St0r@ge!) to control access to its management
interface. A remote attacker can exploit this to gain administrative
access to the web interface.");
  # https://support.quest.com/dr-series/kb/220574/what-are-the-default-login-credentials-for-the-dr-
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5433b84");
  script_set_attribute(attribute:"solution", value:
"Change the default administrative login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score from an in depth analysis done by Tenable");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2022 Tenable Network Security, Inc.");

  script_dependencies("quest_dr_series_web_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("installed_sw/Quest DR Series Appliance");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("http.inc");
include("webapp_func.inc");

var app = "Quest DR Series Appliance";
get_install_count(app_name:app, exit_if_zero:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

var port = get_http_port(default:443);

var install = get_single_install(app_name:app, port:port);

var dir = install["path"];
var install_url = build_url(port:port, qs:dir);

var user = 'administrator';
var pass = 'St0r@ge!';

var data = '{"jsonrpc":"2.0","method":"Logon","params":{"UserName":"' + user + '","Password":"' + pass + '"},"id":1}';

var url = '/ws/v1.0/jsonrpc';
var res = http_send_recv3(
  method       : "POST",
  item         : url,
  port         : port,
  content_type : "application/json",
  data         : data,
  exit_on_fail : TRUE
);

if (!empty_or_null(res))
{
  var headers = parse_http_headers(headers:res[1]);

  if (res[0] =~ "^HTTP/[0-9.]+ +200" && headers['content-type'] =~ "^application/json(-rpc)?" &&
      '"userRole":' >< res[2] && '"SessionCookie":' >< res[2] &&
      '"error":' >!< res[2])
  {
    var header = 'Nessus was able to gain access using the following URL';
    var trailer =
      'and the following set of credentials :\n' +
      '\n' +
      '  Username : ' + user + '\n' +
      '  Password : ' + pass;

    var report = get_vuln_report(items:dir, port:port, header:header, trailer:trailer);

    security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
    exit(0);
  }
}

audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
