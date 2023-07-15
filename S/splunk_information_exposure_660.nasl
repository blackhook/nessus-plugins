#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(121163);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/30");

  script_cve_id("CVE-2018-11409");
  script_xref(name:"IAVA", value:"2021-A-0502-S");

  script_name(english:"Splunk Information Exposure (SP-CAAAP5E");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by
an information exposure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Splunk
running on the remote web server is Splunk Enterprise 6.x prior to 
6.6.0. Therefore it is affected by an information disclosure
vulnerability at a Splunk REST endpoint. An unauthenticated, remote 
attacker can exploit this via the submission a specially crafted 
request, to disclose potentially sensitive information about the 
operating system, hardware and Splunk license.");
  script_set_attribute(attribute:"see_also", value:"https://www.splunk.com/view/SP-CAAAP5E");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Splunk Enterprise version 6.6.0 or later.");
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

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("splunkd_detect.nasl", "splunk_web_detect.nasl");
  script_require_keys("installed_sw/Splunk");
  script_require_ports("Services/www", 8089, 8000);

  exit(0);
}

include("vcf.inc");
include("http.inc");

app = "Splunk";
port = get_http_port(default:8000, embedded:TRUE);

app_info = vcf::get_app_info(app:app, port: port);
if (app_info['License'] == "Enterprise")
{
  constraints = [{ "min_version" : "6.2.0", "fixed_version" : "6.6.0" }];
}
else
  audit(AUDIT_LISTEN_NOT_VULN, 'Splunk', port);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
