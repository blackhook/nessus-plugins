#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(164810);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/26");

  script_cve_id("CVE-2022-36804");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/10/21");

  script_name(english:"Atlassian Bitbucket < 7.6.17 / 7.17.10 / 7.21.4 / 8.0.4 / 8.1.3 / 8.2.2 / 8.3.1 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The version of Atlassian Bitbucket installed on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Bitbucket installed on the remote host 7.0.0 prior to 7.6.17, 7.7.0 prior to 7.17.10, 7.18.0
prior to 7.21.4, 8.0 prior to 8.0.3, 8.1 prior to 8.1.3, 8.2 prior to 8.2.2 or 8.3 prior to 8.3.1. It is, therefore,
affected by a remote code execution vulnerability. A remote attacker with read permissions to a public or private
Bitbucket repository can send a malicious HTTP request leading to arbitrary code execution.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/BSERV-13438");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 7.6.17, 7.17.10, 7.21.4, 8.0.3, 8.1.3, 8.2.2, 8.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-36804");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Bitbucket Git Command Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:bitbucket");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bitbucket_detect.nbin");
  script_require_keys("installed_sw/bitbucket");
  script_require_ports("Services/www", 7990);

  exit(0);
}
include('http.inc');
include('vcf.inc');

var port = get_http_port(default:7990);

var app = 'bitbucket';

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version' : '7.0.0', 'fixed_version' : '7.6.17' },
  { 'min_version' : '7.7.0', 'fixed_version' : '7.17.10' },
  { 'min_version' : '7.18.0', 'fixed_version' : '7.21.4' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.3' },
  { 'min_version' : '8.1.0', 'fixed_version' : '8.1.3' },
  { 'min_version' : '8.2.0', 'fixed_version' : '8.2.2' },
  { 'min_version' : '8.3.0', 'fixed_version' : '8.3.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

