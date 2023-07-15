#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136931);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/28");

  script_cve_id("CVE-2018-8004");

  script_name(english:"Apache Traffic Server - HTTP Smuggling and Cache poisoning");

  script_set_attribute(attribute:"synopsis", value:
"The remote caching server is affected by a HTTP Smuggling and Cache Poisoning vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the result of a remote check, the target Apache Traffic Server does not have a patch applied to mitigate 
HTTP Smuggling and HTTP cache poisoning which was put in place in versions greater than 6.2.3 and 7.1.4. A remote 
unauthenticated attacker could exploit this to gain access to backend resources that they would otherwise not have 
access to.");
  script_set_attribute(attribute:"see_also", value:"https://nvd.nist.gov/vuln/detail/CVE-2018-8004");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Traffic Server version 6.x users should upgrade to 6.2.3 or later. 7.x versions should upgrade to
7.1.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8004");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:traffic_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_traffic_server_version.nasl");
  script_require_keys("www/apache_traffic_server");

  exit(0);
}
include('debug.inc');
include('http.inc');
include('vcf.inc');

var appname = 'Apache Traffic Server';
var app_info = vcf::combined_get_app_info(app:appname);
var port = app_info.port;
var version = app_info.version;

var soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

var req = 'GET /something.html HTTP/1.1\r\n
\r\n
GET /something_else.html HTTP/1.1\r\n
\r\n';

send(socket:soc, data:req);
var response_data = recv(socket:soc, length:2048);

dbg::log(src:SCRIPT_NAME,msg:'\nRequest, Port ' + port + ':\n' + req + '\n' +
                             'Response, Port ' + port + ':\n' + response_data);

var line, vuln, count;

if (response_data) 
{
  count = 0;
  foreach line (split(response_data)) 
  {
    if (egrep(pattern:"HTTP/1.[0-2] 400", string:line)) 
      count += 1;
  }
  if (count == 2) 
    vuln = TRUE;
  else 
  {
    dbg::log(src:SCRIPT_NAME,msg:'(Port ' + port + ') Only one request processed, target is patched.');
    vuln = FALSE;
  }
}

else 
{
  dbg::log(src:SCRIPT_NAME,msg:'(Port ' + port + ') No response recieved from target.');
  vuln = FALSE;
}

dbg::log(src:SCRIPT_NAME, msg:'Vuln State: ' + vuln);

var fixed, caveat, report;

if (vuln == TRUE) 
{
  if (version =~ "^7\.0.[1-9]|7\.1.[0-3]") 
    fixed = '7.1.4';
  else if (version =~ "^6\.0.[0-9]|6\.1.[0-9]|6\.2.[0-2]") 
    fixed = '6.2.3';
  else 
    fixed = '6.2.3 or 7.1.4';
    
  # As this is a direct check, adding caveat to output if version is not a known affected version
  caveat = '\nThis plugin has exploited the vulnerability. If the installed version of Apache Traffic Server is not \n' + 
          'a known affected version (refer to vendor advisory), please contact the vendor to ensure that there has \n' +
          'not been a regression, or, if this may be a newly discovered issue.\n';

  report =
    '\n  Installed version      : ' + version +
    '\n  Fixed version          : ' + fixed + '\n';

  if (fixed == '6.2.3 or 7.1.4')
    report += caveat;

  else 
    report += '\nA vulnerable version of Apache Traffic Server was found to be installed.\n';

  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}

else
  audit(AUDIT_LISTEN_NOT_VULN, 'Apache Traffic Server', port);
