#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160201);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_name(english:"QNAP QTS / QuTS Hero Default Credentials");

  script_set_attribute(attribute:"synopsis", value:
"The application hosted on the remote web server uses a default set of known credentials.");
  script_set_attribute(attribute:"description", value:
"The remote QNAP QTS or QuTS Hero web administration interface uses a known set of hard-coded default credentials. An
attacker can exploit
this to gain administrative access to the remote host.");
  script_set_attribute(attribute:"solution", value:
"Change the application's default credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of vulnerability");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:quts_hero");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 Tenable Network Security, Inc.");

  script_dependencies("qnap_qts_quts_hero_web_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("installed_sw/QNAP QTS");

  exit(0);
}

include('http.inc');
include('url_func.inc');
include('webapp_func.inc');
include('spad_log_func.inc');

get_kb_item_or_exit('installed_sw/QNAP QTS');

##
# Try to authenticate with default admin/admin creds
#
# @param port The port QNAP QTS/QuTS Hero was detected on
# @return TRUE for successful authentication, otherwise FALSE
##
function try_default_creds(port)
{
  spad_log(message:'in tdc\n');
  var res, post;
  # pwd = urlencode(base64encode(admin))
  post = 'user=admin&serviceKey=1&pwd=YWRtaW4%3D';
  # Authenticate
  res = http_send_recv3(
    port         : port,
    method       : 'POST',
    item         : '/cgi-bin/authLogin.cgi',
    data         : post,
    content_type : "application/x-www-form-urlencoded",
    exit_on_fail : TRUE
  );

  spad_log(message:'Attempted to login with: ' + http_last_sent_request());
  spad_log(message:'Response was: ' + obj_rep(res));
  if ('pw_status' >< res[2] && 'authSid' >< res[2] && 'isAdmin' >< res[2])
    return TRUE;

  return FALSE;
}

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

var app = 'QNAP QTS';
get_install_count(app_name:app, exit_if_zero:TRUE);
var port = get_http_port(default:443);
var install  = get_single_install(app_name:app,port:port);
var url      = build_url(port:port, qs:install['path']);

var can_auth = try_default_creds(port:port);

var report, header, trailer;
if (can_auth)
{
  report += '\n' +
            '\n  Username : admin'
            '\n  Password : admin';
}

if (report != '')
{
  header  = 'Nessus was able to gain access using the following URL';
  trailer = 'and the following set of credentials :' + report;
  report  = get_vuln_report(
    items     : install['path'],
    port      : port,
    header    : header,
    trailer   : trailer
  );
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);
