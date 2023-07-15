###
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118331);
  script_version("1.1");
  script_cvs_date("Date: 2018/10/24 10:33:48");

  script_name(english:"QLogic QConvergeConsole (QCC) GUI Web Interface Default Credentials");
  script_summary(english:"Tries to login with the default credentials");

  script_set_attribute(attribute:"synopsis", value:
"The remote web interface is protected with a default password.");
  script_set_attribute(attribute:"description", value:
"The remote device appears to be running QLogic QConvergeConsole which
 contains a web interface with default credentials enabled.");
  script_set_attribute(attribute:"solution", value:
"Replace the default password with a strong password.");
  
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"NVD score unavailable. Assigned score for web interface default credentials.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/24");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:qlogic:qconvergeconsole");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qcc_detect.nbin");
  script_require_keys("installed_sw/QLogic QConvergeConsole");
  script_require_ports("Services/www", 8080, 8443);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

get_install_count(app_name:app, exit_if_zero:TRUE);

app = "QLogic QConvergeConsole";
port = get_http_port(default:8080);
 
install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];

function qcc_login(username, password)
{
  local_var postdata =
  "j_username=" + username + "&" +
  "j_password=" + password + "&" +
  "j_character_encoding=UTF-8";

  clear_cookiejar();

  #doesn't work without this initial request
  local_var login_res = http_send_recv3(port:port,
  method:'GET',
  item:'/QConvergeConsole/');

  #post request to QCC GUI Login
  local_var res = http_send_recv3(
  port:port,
  method:          "POST",
  item:            "/QConvergeConsole/j_security_check",
  data:            postdata,
  content_type:    "application/x-www-form-urlencoded",
  follow_redirect: 1,
  exit_on_fail:    TRUE);

  # The server will always respond with 200 OK, but success should also
  # include the JSESSIONID cookie getting set.
  if ("200 OK" >!< res[0] || "Set-Cookie: JSESSIONID=" >!< res[1] || "com.qlogic.qms.hba.gwt.Main" >!< res[2])
  {
    return FALSE;
  }

  return TRUE;
}

results = NULL;

if (qcc_login(username:"QCC", password:"config") == TRUE)
{
  results += 'QCC/config\n';
}

if (empty_or_null(results)) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(port:port, qs:dir));

report = 
  '\n' + "Nessus was able to log into the remote web interface" +
  '\n' + "using the following default credentials :" +
  '\n' +
  '\n' + results;
security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
exit(0);
