#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136763);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/21");

  script_name(english:"IBM MQ Default Credentials");

  script_set_attribute(attribute:"synopsis", value:
"Checks if IBM MQ is using default credentials.");
  script_set_attribute(attribute:"description", value:
"The remote host is running IBM MQ and REST API and is using default credentials. An unauthenticated, remote attacker
can exploit this gain privileged or administrator access to the system.");
  script_set_attribute(attribute:"solution", value:
"Change the default administrative login credentials.");

  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"score from a more in depth analysis done by Tenable");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_mq_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("installed_sw/IBM MQ");
  exit(0);
}

include('http.inc');
include('debug.inc');
include('install_func.inc');

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

app = 'IBM MQ';
get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:9443);
install = get_single_install(app_name:app, port:port);
url = build_url(port: port, qs:"/ibmmq/");

console = '/ibmmq/console/j_security_check';

# below are the default creds to use if no credentials are supplied by the user
known_default_creds = [['admin','passw0rd'], ['mqadmin','mqadmin']];

authed = FALSE;
foreach creds (known_default_creds) {
  username = creds[0];
  password = creds[1];

  # attempt to authenticate with default credentials
  enable_cookiejar();
  authenticate = http_send_recv3(
      method       : 'POST',
      port         : port,
      item         : console,
      content_type : 'application/x-www-form-urlencoded',
      data         : 'j_username=' + username + '&j_password=' + password,
      exit_on_fail : FALSE,
      follow_redirect : 0
  );

  if (authenticate[1] !~  "login\.html\?error") {
    report =
      '\n' + 'It is possible to log into the IBM MQ Web Console at the' +
      '\n' + 'following URL :' +
      '\n' +
      '\n' +  url + console +
      '\n' +
      '\n' + 'With these credentials : ' + username + '/' + password;

    security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
    authed = TRUE;
  }
  else {
    dbg::log(src:SCRIPT_NAME, msg:'Authentication failed using the default credentials ' + username + ':' + password);
  }
}

if (!authed) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);
