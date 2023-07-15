#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(46740);
  script_version("1.30");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/09");

  script_cve_id("CVE-2010-0219");
  script_bugtraq_id(44055, 45625);
  script_xref(name:"CERT", value:"989719");

  script_name(english:"Apache Axis2 Default Credentials");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that uses default
credentials.");
  script_set_attribute(attribute:"description", value:
"The installation of Apache Axis2 hosted on the remote web server uses
a default set of credentials to control access to its administrative
console. A remote attacker can exploit this to gain administrative
control.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/514284/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2010/Oct/100");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/516029");
  script_set_attribute(attribute:"solution", value:
"Login via the administrative interface and change the password for
the 'admin' account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute: "cvss_score_source", value: "CVE-2010-0219");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Axis2 / SAP BusinessObjects Authenticated Code Execution (via SOAP)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:axis2");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2022 Tenable Network Security, Inc.");

  script_dependencies("apache_axis2_detect.nasl");
  script_require_keys("installed_sw/Axis2");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("http.inc");
include("install_func.inc");

app = "Axis2";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8080);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

user = 'admin';
pass = 'axis2';

login = FALSE;
test_login = FALSE;

# In CA ArcServe D2D, The root dir is /WebServiceImpl
if (dir == '/WebServiceImpl/axis2-web') dir = '/WebServiceImpl';
url = '/axis2-admin/';

# Check if the axis2-admin interface is installed
# As of 2022-11-21 the login page may be at /axis2-admin/welcome
res = http_send_recv3(method:"GET", item:dir+url, port:port, exit_on_fail:TRUE, follow_redirect: 1);

if ('<title>Login to Axis2 :: Administration page</title>' >< res[2])
{
  test_login = TRUE;
}
else
{
  url = "/Login.jsp";
  res = http_send_recv3(method:"GET", item:dir+url, port:port, exit_on_fail:TRUE);

  if (res[2] =~ '<title>Login to Axis2:: (Administration|Administartion) page</title>')
  {
    test_login = TRUE;
  }
}
if (test_login)
{
  # Try GET request first
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : dir + '/adminlogin?userName='+user+'&password='+pass+'&submit=+Login++',
    exit_on_fail : TRUE,
    follow_redirect : 1
  );
  if (
    '<title>Axis2 :: Administrations Page</title>' >< res[2] &&
    '<a href="logout">Log out<' >< res[2]
  )
  {
    login = TRUE;
    rep_url = install_url + url;
  }
  if (!login)
  {
    # Cookie jar for authentication
    init_cookiejar();
    # Authenticate with POST request then access admin console with GET request
    # Older versions of Axis2 may only need the POST request to log in
    postdata = 'userName='+user+'&password='+pass+'&submit=+Login+';
    res = http_send_recv3(
      method: 'POST',
      port: port,
      item: dir + url + 'login',
      content_type: "application/x-www-form-urlencoded",
      data: postdata,
      exit_on_fail: TRUE
    );
    var res_get = http_send_recv3(method: 'GET', port: port, item: dir + url + 'index', exit_on_fail: TRUE);

    if (
      ('<title>Axis2 :: Administration Page</title>' >< res[2] &&
      '<p>You are now logged into the Axis2 administration console' >< res[2]) ||
      ('<title>Axis2 :: Administration Page</title>' >< res_get[2] &&
      '<p>You are now logged into the Axis2 administration console' >< res_get[2])
    )
    {
      login = TRUE;
      rep_url = install_url + url + 'login';
    }
  }
  if (login)
  {
    report =
      '\nNessus was able to gain access to the administrative interface using' +
      '\nthe following information :' +
      '\n' +
      '\n  URL      : ' + rep_url +
      '\n  User     : ' + user +
      '\n  Password : ' + pass + '\n';
      security_report_v4(port: port, severity: SECURITY_HOLE, extra: report);
  }
  else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
}
else exit(0, 'The '+app+' install at  ' + install_url+' does not have an administrative interface.');
