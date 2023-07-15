#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(121164);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/30");

  script_cve_id("CVE-2018-11409");
  script_xref(name:"EDB-ID", value:"44865");
  script_xref(name:"IAVA", value:"2021-A-0502-S");

  script_name(english:"Splunk Information Disclosure Vulnerability (SP-CAAAP5E)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Splunk installation running on the remote web server is affected by an information disclosure vulnerability at a
Splunk REST endpoint. An unauthenticated, remote attacker can exploit this, via a specially crafted request, to disclose
potentially sensitive information");
  # https://www.splunk.com/view/SP-CAAAP5E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eaef4f0a");
  # https://www.exploit-db.com/exploits/44865
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?98482484");
  script_set_attribute(attribute:"solution", value:
"Consult your vendor for a patch or a workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11409");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("splunkd_detect.nasl", "splunk_web_detect.nasl");
  script_require_keys("installed_sw/Splunk");
  script_require_ports("Services/www", 8089, 8000);

  exit(0);
}

include('global_settings.inc');
include('webapp_func.inc');
include('http.inc');
include('debug.inc');

app = 'Splunk';
port = get_http_port(default:8000, embedded:TRUE);
get_install_from_kb(appname:app, port:port, exit_on_fail:TRUE);

req = '/en-US/splunkd/__raw/services/server/info/server-info?output_mode=json';
res = http_send_recv3(method:'GET', item:req, port:port);
dbg::log(msg:'Request:\n' + http_last_sent_request() + '\n');
dbg::log(msg:'Response:\nSTATUS:\n' + res[0] + '\nHEADERS:\n' + res[1] + '\nBODY:\n' + res[2] + '\n');

matches = pregmatch(pattern: '"os_name":"(.*?)"', string:res[2]);
if (!isnull(matches)) os_name = matches[1];
else os_name = '';

matches = pregmatch(pattern: '"os_version":"(.*?)"', string:res[2]);
if (!isnull(matches)) os_version = matches[1];
else os_version = '';

matches = pregmatch(pattern: '"product_type":"(.*?)"', string:res[2]);
if (!isnull(matches)) product_type = matches[1];
else product_type = '';

matches = pregmatch(pattern: '"serverName":"(.*?)"', string:res[2]);
if (!isnull(matches)) server_name = matches[1];
else server_name = '';

matches = pregmatch(pattern: '"version":"(.*?)"', string:res[2]);
if (!isnull(matches)) product_version = matches[1];
else product_version = '';

if (!(os_name | os_version | product_type | server_name | product_version))
  audit(AUDIT_LISTEN_NOT_VULN,'Splunk' , port);

report = 'Nessus was able to exploit the issue by sending the following request:\n' + req;
report += '\n\nThe following information was retrieved:\n';
if (os_name) report += 'OS name: ' + os_name + '\n';
if (os_version) report += 'OS version: ' + os_version + '\n';
if (product_type) report += 'Product type: ' + product_type + '\n';
if (product_version) report += 'Product version: ' + product_version + '\n';
if (server_name) report += 'Server name: ' + server_name + '\n';

security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
