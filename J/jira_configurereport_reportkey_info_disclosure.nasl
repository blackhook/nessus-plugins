#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(48263);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(42025);

  script_name(english:"Atlassian JIRA ConfigureReport.jspa 'reportKey' Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Atlassian JIRA installation hosted on the remote web server is
affected by an information disclosure vulnerability, which an
unauthenticated attacker can exploit, by setting the 'reportKey'
parameter in ConfigureReport.jspa to an invalid value, to gain access
to sensitive information, such as operating system version, database
version, or build version from the remote system.

This version of JIRA is also reportedly affected by multiple
cross-site scripting vulnerabilities; however, Nessus has not tested
for these issues.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2010/Jul/254");
  script_set_attribute(attribute:"see_also", value:"https://id.atlassian.com/login?continue=https%3A%2F%2Fid.atlassian.com%2Fopenid%2Fv2%2Fop%3Fopenid.return_to%3Dhttps%3A%2F%2Fconfluence.atlassian.com%2Fplugins%2Fservlet%2Fauthentication%3Fauth_plugin_original_url%253D%25252Fjirakb%25252Fremove-information-from-the-500-error-page-oops-an-error-has-occurred-282174657.html%26openid.ns%3Dhttp%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%26openid.ns.sreg%3Dhttp%3A%2F%2Fopenid.net%2Fsreg%2F1.0%26openid.assoc_handle%3D11685648%26openid.identity%3Dhttp%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select%26openid.realm%3Dhttps%3A%2F%2F*.atlassian.com%26openid.claimed_id%3Dhttp%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select%26openid.sreg.required%3Dfullname%2Cnickname%2Cemail%26openid.mode%3Dcheckid_setup&prompt=&application=&tenant=&email=&errorCode=");
  script_set_attribute(attribute:"solution", value:
"Modify the JIRA 500 error page as discussed in the vendor's knowledge
base article.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl");
  script_require_keys("installed_sw/Atlassian JIRA");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");
include("data_protection.inc");

app = "Atlassian JIRA";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8080);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];

# Try to find a valid id.
start = 10000;

if (thorough_tests) end = 10100;
else end = 10040;

pid = '';

for (i = start ; i < end ; i+=10)
{
  url = dir + "/ViewProject.jspa?pid="+i;
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
  if (
    (
      "You cannot view this URL as a guest." >< res[2] ||
      ">Project Category:<" >< res[2] ||
      ">Project Team:<" >< res[2]
    ) &&
    "There is not a project with the specified id" >!< res[2]
  )
  {
    pid = i;
    break;
  }
}
# In some testing cases, the project id was not needed so test anyways
if (!pid) pid = '1000';

url = "/ConfigureReport.jspa?selectedProjectId="+pid+"&reportKey="+SCRIPT_NAME+'-'+unixtime()+"&Next=Next";
res = http_send_recv3(method:"GET", item:dir+url, port:port, exit_on_fail:TRUE);
# Look for strings that indicate information disclosure...
if(
  ">Oops - an error has occurred<" >< res[2] &&
  ">System Information:" >< res[2] &&
  ">Build Information:" >< res[2]
)
{
  out = strstr(res[2], "Build Information:");
  if (!empty_or_null(out))
  {
    foreach line (split(out, sep:"<br />", keep:FALSE))
    if (line =~ "^[a-zA-Z0-9. :]+$")
         output += line + '\n';
  }
  else output = res[2];

  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    generic    : TRUE,
    request    : make_list(build_url(qs:dir+url, port:port)),
    output     : data_protection::sanitize_user_full_redaction(output:chomp(output))
  );
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:dir, port:port));
