#
# (C) Tenable Network Security, Inc.
#
# Based on the original work of David Kyger, revised by Tenable in 2019.
#

include("compat.inc");

if(description)
{
  script_id(12085);
  script_version ("1.22");
  script_cvs_date("Date: 2019/08/12 16:00:54");

  script_name(english:"Apache Tomcat Default Files");
  script_summary(english:"Checks for Apache Tomcat default files.");

  script_set_attribute(attribute:"synopsis", value: "The remote web server contains default files.");
  script_set_attribute(attribute:"description", value:
"The default error page, default index page, example JSPs and/or example servlets are installed on the remote Apache
Tomcat server. These files should be removed as they may help an attacker uncover information about the remote Tomcat
install or host itself.");
  #https://cwiki.apache.org/confluence/display/TOMCAT/Miscellaneous#Miscellaneous-Q6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4cb3b4dd");
  script_set_attribute(attribute:"see_also", value:"https://www.owasp.org/index.php/Securing_tomcat");
  script_set_attribute(attribute:"solution", value:
"Delete the default index page and remove the example JSP and servlets. Follow the Tomcat or OWASP instructions to 
replace or modify the default error page.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on typical Information Disclosure 
  vulnerability");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/03/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Web Servers");

  script_dependencies("tomcat_error_version.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("installed_sw/Apache Tomcat");
  exit(0);
}

include('global_settings.inc');
include('http.inc');
include('audit.inc');

port = get_http_port(default:8080);

# Only run against Tomcat targets
get_kb_item_or_exit('www/' + port + '/tomcat');

urls = make_list(
  '/index.html',
  '/docs/', # version 7+
  '/tomcat-docs/index.html', # version 4-6
  '/examples/servlets/index.html',
  '/examples/jsp/index.html',
  '/examples/websocket/index.xhtml');

found_files = '';
foreach(url in urls)
{
  resp = http_send_recv3(method:'GET', item:url, port:port);
  if (isnull(resp)) continue;

  resp_body = resp[2];

  if ('It works !' >< resp_body && 'it means you\'ve setup Tomcat successfully.' >< resp_body ||
      'you\'ve successfully installed Tomcat.' >< resp_body && 'tomcat-users.xml' >< resp_body ||
      'Documentation Index' >< resp_body && 'Apache Software Foundation' ||
      'Examples with Code' >< resp_body && 'Servlet API' >< resp_body ||
      'Java Server Pages' >< resp_body && 'session scoped beans' ||
      'Apache Tomcat WebSocket Examples' >< resp_body && 'echo.xhtml' >< resp_body)
  {
    found_files += ('\n' + build_url(qs:url, port:port));
  }
}

# Request a purposely non-existent url so a 404 is returned.
url_404 = '/nessus-check/default-404-error-page.html';
resp_404 = http_send_recv3(method: 'GET', item:url_404, port:port, fetch404:TRUE, exit_on_fail:TRUE);
response = resp_404[2];

report = '';
if (!empty(found_files)) report = '\nThe following default files were found :\n'+found_files+'\n';

if ( 'Apache Tomcat/' >< response &&
    (('origin server' >< response && 'target resource' >< response) || 'HTTP Status 404' >< response))
  report += '\nThe server is not configured to return a custom page in the event of a client requesting a non-existent '
  + 'resource.\nThis may result in a potential disclosure of sensitive information about the server to attackers.\n';

if (empty(report)) audit(AUDIT_LISTEN_NOT_VULN, 'Apache Tomcat', port);

security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
