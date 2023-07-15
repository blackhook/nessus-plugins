#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106719);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2018/02/09 21:55:16 $");

  script_name(english:"Nokia VitalQIP Web Client Default Credentials");
  script_summary(english:"Tries to login with the default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web interface is protected with a default password.");
  script_set_attribute(attribute:"description", value:
"The remote device appears to be a Nokia VitalQIP which contains a web
interface with default credentials enabled.");
  script_set_attribute(attribute:"solution", value:
"Replace the default password with a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/09");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:nokia:vitalqip");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:alcatel-lucent:vitalqip");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");

  script_dependencies("vitalqip_web_client_detect.nbin");
  script_require_keys("installed_sw/VitalQIP Web Client");
  script_require_ports("Services/www", 443, 743, 8080);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

app = 'VitalQIP Web Client';
get_install_count(app_name:app, exit_if_zero:TRUE);

item = "/qip";
port = get_http_port(default:743);

install = get_single_install(app_name:app, port:port);
url = build_url(qs:item, port:port);

init_cookiejar();

# Make an initial request to retrieve cookie
res = http_send_recv3(method:"GET", item:item, port:port, exit_on_fail:TRUE);
if (res[0] !~ '^HTTP/[0-9.]+ +200')
  exit(1, "Unexpected HTTP status code received after requesting " + url + ".");
if ("<title>VitalQIP Login</title>" >!< res[2])
  exit(1, "Unexpected HTTP webpage received after requesting " + url + ".");


creds = [[ 'qipadmin', 'qipadmin' ],
         [ 'qipman', 'qipman' ]];

report = NULL;

foreach cred (creds)
{
  username = cred[0];
  password = cred[1];

  postdata = 'srvAction=LoginAdmin&login=' + username + '&password=' + password + '&Submit=Login&select_locale=en';

  res = http_send_recv3(
    method          : "POST",
    item            : item,
    data            : postdata,
    port            : port,
    add_headers     : {'Content-Type':'application/x-www-form-urlencoded'},
    follow_redirect : 1,
    exit_on_fail    : TRUE
  );

  # Server should response with a 200 HTTP status code with correct or incorrect credentials
  if (res[0] !~ '^HTTP/[0-9.]+ +200') continue;

  if (
    'Invalid username/password' >!< res[2] &&
    '<input id="password"' >!< res[2] &&
    '<select name="selectOrganization" id="selectOrganization">' >< res[2] &&
    '<form method="post" name="orgSelectForm"' >< res[2]
  )
    report += '\n  Username : ' + username +
              '\n  Password : ' + password +
              '\n';
}

if (!empty_or_null(report))
{
  report = 
    '\nNessus was able to log into the ' + app + ' using the' +
    '\nfollowing information :' +
    '\n' +
    '\n  URL      : ' + url +
    report;
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
  exit(0);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);
