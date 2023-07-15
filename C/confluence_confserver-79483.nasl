##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163327);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/08");

  script_cve_id("CVE-2022-26138");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/19");

  script_name(english:"Atlassian Confluence < 7.4.17 / 7.13.x < 7.13.6 / < 7.14.3 / 7.15.x < 7.15.2 / 7.16.x < 7.16.4 / 7.17.x < 7.17.2 (CONFSERVER-79483)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Confluence host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Confluence installed on the remote host is prior to < 7.4.17 / 7.13.x < 7.13.6 / 7.14.x <
7.14.3 / 7.15.x < 7.15.2 / 7.16.x < 7.16.4 / 7.17.x < 7.17.2. It is potentially affected by a hard-coded credential
vulnerability if the 'Questions for Confluence' app is installed.

The Atlassian Questions For Confluence app for Confluence Server and Data Center creates a Confluence user account in
the confluence-users group with the username disabledsystemuser and a hardcoded password. A remote, unauthenticated
attacker with knowledge of the hardcoded password could exploit this to log into Confluence and access all content
accessible to users in the confluence-users group. This user account is created when installing versions 2.7.34, 2.7.35,
and 3.0.2 of the app.(CVE-2022-26138)

Note that Nessus has not tested for this issue but has instead relied only on Confluence's self-reported version
number. This plugin will only run in 'Parnoid' scans.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-79483");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 7.4.17, 7.13.6, 7.14.3, 7.15.2, 7.16.4, 7.17.2, 7.13.6, 7.14.3, 7.15.2, 7.16.4,
7.17.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26138");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("confluence_detect.nasl");
  script_require_keys("installed_sw/confluence", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8080, 8090);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:80);
var app_info = vcf::get_app_info(app:'confluence', port:port, webapp:true);

# The vuln is in the Questions for Confluence app, not Confluence itself
# We cannot determin if this is installed and/or the offending user account is present
if (report_paranoia < 2) audit(AUDIT_POTENTIAL_VULN, 'Confluence', app_info.version);

var constraints = [
  { 'fixed_version' : '7.4.17', 'fixed_display' : '7.4.17 / 7.13.6 / 7.14.3 / 7.15.2 / 7.16.4 / 7.17.2' },
  { 'min_version' : '7.13.0', 'fixed_version' : '7.13.6' },
  { 'min_version' : '7.14.0', 'fixed_version' : '7.14.3' },
  { 'min_version' : '7.15.0', 'fixed_version' : '7.15.2' },
  { 'min_version' : '7.16.0', 'fixed_version' : '7.16.4' },
  { 'min_version' : '7.17.0', 'fixed_version' : '7.17.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
