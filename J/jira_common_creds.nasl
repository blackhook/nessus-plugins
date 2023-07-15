#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123003);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Atlassian JIRA Common Credentials");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is protected using a common set of 
credentials.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to gain access to the Atlassian JIRA web application
using a common set of credentials. A remote attacker can exploit this 
issue to disclose sensitive information or otherwise affect the 
operation of the application and underlying system.");
  script_set_attribute(attribute:"solution", value:
"Change or remove the affected set of JIRA credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for default credentials.");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl");
  script_require_keys("installed_sw/Atlassian JIRA");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("install_func.inc");
include("spad_log_func.inc");

if (supplied_logins_only)
  audit(AUDIT_SUPPLIED_LOGINS_ONLY);

get_install_count(app_name:"Atlassian JIRA", exit_if_zero:TRUE);
port = get_http_port(default:8080);
install = get_single_install(app_name:"Atlassian JIRA", port:port);

 # Adding this as a workaround to use basic auth directly 
 # / in all requests made by http_send_recv3 / http_network.inc
 _basic_auth_URLs["/login.jsp"]=1;

n = 0;
user[n] = "jira"; pass[n++] = "jira";
user[n] = "admin";	pass[n++] = "admin";

function test(port, user, pass)
{
 local_var	r;

 r = http_send_recv3(
   port : port,
   username : user,
   password : pass,
   method : "GET",
   item : "/login.jsp",
   exit_on_fail : TRUE
 );
 spad_log(message:'Request:\n' + http_last_sent_request());
 spad_log(message:'Response:\n' + obj_rep(r));

 if (r[0] !~ "^HTTP/1\.[01] 200" || "AUTHENTICATED_FAILED" >< r[1] || "<title>Log in" >< r[2]) return 0;
 else return 1;
}

url = build_url(port: port, qs:"login.jsp");
report = '';

clear_cookiejar();

for (i = 0; i < n; i ++)
{
  if (test(port: port, user: user[i], pass: pass[i]))
  {
    report +=
      '\n  URL      : ' + url +
      '\n  Username : ' + user[i] +
      '\n  Password : ' + pass[i] + '\n';
    break;
  }
}

if (!empty_or_null(report))
{
  report = '\nIt was possible to log into the Atlassian JIRA web app using the\nfollowing info :\n' + report;
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Atlassian JIRA", port);
