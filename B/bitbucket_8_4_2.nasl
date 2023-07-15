#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(170143);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/17");

  script_cve_id("CVE-2022-43781");

  script_name(english:"Atlassian Bitbucket < 7.6.19 / 7.17.12 / 7.21.6 / 8.0.5 / 8.1.5 / 8.2.4 / 8.3.3 / 8.4.2 Command Injection");

  script_set_attribute(attribute:"synopsis", value:
"The version of Atlassian Bitbucket installed on the remote host is affected by a command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Bitbucket installed on the remote host 7.0.0 prior to 7.6.19, 7.7.0 prior to 7.17.12, 7.18.0
prior to 7.21.6, 8.0 prior to 8.0.5, 8.1 prior to 8.1.5, 8.2 prior to 8.2.4, 8.3 prior to 8.3.3 or 8.4 prior to 8.4.2. 
It is, therefore, affected by a command injection vulnerability using environment variables in Bitbucket Server and 
Data Center. An attacker with permission to control their username can exploit this issue to gain code execution and 
execute code on the system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://confluence.atlassian.com/bitbucketserver/bitbucket-server-and-data-center-security-advisory-2022-11-16-1180141667.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e5cea2f");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/BSERV-13522");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 7.6.19, 7.17.12, 7.21.6, 8.0.5, 8.1.5, 8.2.4, 8.3.3, 8.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-43781");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Bitbucket Environment Variable RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/18");

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
  { 'min_version' : '7.0.0', 'fixed_version' : '7.6.19' },
  { 'min_version' : '7.7.0', 'fixed_version' : '7.17.12' },
  { 'min_version' : '7.18.0', 'fixed_version' : '7.21.6' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.5' },
  { 'min_version' : '8.1.0', 'fixed_version' : '8.1.5' },
  { 'min_version' : '8.2.0', 'fixed_version' : '8.2.4' },
  { 'min_version' : '8.3.0', 'fixed_version' : '8.3.3' },
  { 'min_version' : '8.4.0', 'fixed_version' : '8.4.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

