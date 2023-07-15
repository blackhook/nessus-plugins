#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124086);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/16 13:38:59");

  script_name(english:"HP DesignJet Accounting.xls Information Disclosure Vulnerability");
  script_summary(english:"Tries to read the accounting.xls file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote printer is affected by an information disclosure
vulnerability." );
  script_set_attribute(attribute:"description", value:
"The HP DesignJet printer is affected by an information disclosure
vulnerability due to exposure of the accounting.xls file. An
unauthenticated, remote attacker can exploit this to disclose printer
user names, document titles, and other information on print jobs.");
  script_set_attribute(attribute:"solution", value:"Secure access to the accounting.xls page.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on analysis of the vulnerability.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:hp:designjet");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_www_detect.nbin", "hp_designjet_web_interface_detect.nbin");
  script_require_ports("Services/www", 80, 443, 8080);
  script_require_keys("installed_sw/Embedded HP Server");
  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('http5.inc');
include('vcf.inc');

app = 'Embedded HP Server';

port = get_http_port(default:443);
app_info = vcf::get_app_info(app:app, port:port);

# Try to exploit the flaw.
url = 'hp/device/webAccess/accounting.xls';

res = http_send_recv3(port:port, method:'GET', item:url);
if (isnull(res)) audit(AUDIT_RESP_NOT, port, 'GET request to ' + url);

vuln = FALSE;

# Lets check if this a valid accounting file with feild that have sesitive data
if(preg(string:res[2], pattern:'<title>Accounting</title>', multiline:TRUE) &&
  (preg(string:res[2], pattern:'<th>Document</th>', multiline:TRUE) ||
   preg(string:res[2], pattern:'<th>User name</th>', multiline:TRUE) ||
   preg(string:res[2], pattern:'<th>Account ID</th>', multiline:TRUE))
)
{
  # We need to check if there is more than one row.
  # The best way is to count the number of <tr> row tags.
  count = 0;
  string = res[2];

  while(string = strstr(string, '</tr>'))
  {
    string = string - '</tr>';
    count++;

    if (count > 1)
    {
      vuln = TRUE;
      break;
    }
  }
}

if (vuln)
{
  output = data_protection::sanitize_user_full_redaction(output:res[2]);
  security_report_v4(port:port, severity:SECURITY_WARNING, generic:TRUE, request:[http_last_sent_request()], output:output);
}
else
  audit(AUDIT_HOST_NOT, 'affected');
