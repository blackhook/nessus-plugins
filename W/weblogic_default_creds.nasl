#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43352);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/14");

  script_name(english:"Oracle WebLogic Default Credentials");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application uses default credentials.");
  script_set_attribute(attribute:"description", value:
"It is possible to log into the remote WebLogic installation by
providing the default credentials.  A remote attacker could exploit this
to gain administrative control of this installation.");
  script_set_attribute(attribute:"solution", value:
"Secure any default accounts with a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Default score for default credentials");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("weblogic_detect.nasl");
  script_require_keys("www/weblogic");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 7001);

  exit(0);
}

include('http.inc');
include('lists.inc');


# globals
var appname = 'WebLogic';
get_kb_item_or_exit('www/weblogic');
var port = get_http_port(default:7001);
get_kb_item_or_exit('www/weblogic/' + port + '/installed');

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

var url = '/console';
var full_url = build_url(qs:url, port:port);

var accounts = [
  ['weblogic', 'weblogic'],
  ['system',   'password'],
  ['system',   'Passw0rd'],
  ['adminuser','Webl0gic!'],
  ['people',   'peop1e'],
  ['weblogic', 'password'],
  ['system',   'weblogic'],
  ['weblogic', 'welcome1'],
  ['weblogic', 'weblogic1']
];

# tries to login with the given username (arg1) and password (arg2)
function login()
{
  local_var user, pass, res, res_hdrs, postdata, logged_in;
  user = _FCT_ANON_ARGS[0];
  pass = _FCT_ANON_ARGS[1];
  logged_in = FALSE;

  postdata = 'j_username='+user+'&j_password='+pass;
  res = http_send_recv3(
    method:'POST',
    item:url+'/j_security_check',
    data:postdata,
    content_type:'application/x-www-form-urlencoded',
    port:port,
    exit_on_fail:TRUE
  );

  dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:'Postdata Response:\nSTATUS:\n' + res[0] + '\nHEADERS:\n' + res[1] + '\nBODY:\n' + res[2] + '\n');

  if ('Authentication Denied' >< res[2]) return FALSE;

  # A successful login will result in three redirects.  This will only check
  # for the first
  res_hdrs = parse_http_headers(status_line:res[0], headers:res[1]);

  dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:'Parsed Response : \n' + obj_rep(res_hdrs) + '\n');

  if (!isnull(res_hdrs) && preg(string:res_hdrs['location'], pattern:url+'/index.jsp$'))
  {
    dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:'Successful login indicated due to redirecting to '+ res_hdrs.location + '\n\n');
    logged_in = TRUE;
  }

  return logged_in;
}


#
# script begins here
#

var success = make_list();

var res = http_send_recv3(method:'GET', item:url, port:port, follow_redirect:2, exit_on_fail:TRUE);

dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:'Original Get Response:\nSTATUS:\n' + res[0] + '\nHEADERS:\n' + res[1] + '\nBODY:\n' + res[2] + '\n');

if (
  '<TITLE>BEA WebLogic Server Administration Console</TITLE>' >!< res[2] &&
  '<title>Oracle WebLogic Server Administration Console</title>' >!< res[2] &&
  '<TITLE>WebLogic Server' >!< res[2]
)
{
  audit(AUDIT_INST_VER_NOT_VULN, appname);
}

var account, user, pass, report;

foreach account (accounts)
{
  user = account[0];
  pass = account[1];
  if (login(user, pass))
  {
    collib::push(account, list:success);
    if (!thorough_tests) break;
  }
}

if (max_index(success) > 0)
{
  report =
    '\n' +
    'Nessus was able to login using the following information :\n\n' +
    'URL      : '+full_url+'\n';

  foreach account (success)
    report += 'Login credentials : '+account[0]+' / '+account[1]+'\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, full_url);
