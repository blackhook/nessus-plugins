#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129406);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/21");

  script_cve_id("CVE-2019-14994");

  script_name(english:"Atlassian JIRA Service Desk Path Traversal Vulnerability (2019-09-18)");
  script_summary(english:"Checks the version of Atlassian JIRA.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is potentially affected by a path traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of 
 Atlassian Service Desk hosted on the remote web server is 
 prior to 3.9.16, 3.1x.x prior to 3.16.8, 4.0.x prior to 4.1.3, 4.2.x 
 prior to 4.2.5, 4.3.x prior to 4.3.4, 4.4.x prior to 4.4.1. It is, 
 therefore, affected by an url path traversal vulnerability 
 in Jira Service Desk Server and Jira Service Desk Data Center. 
 An authenticated, remote attacker can exploit this to view all 
 issues from all the projects in the affected instance.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JSDSERVER-6517");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian JIRA Service Desk Server 
  3.9.16 / 3.16.8 / 4.1.3 / 4.2.5 / 4.3.4 / 4.4.1 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14994");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_service_desk_installed_win.nbin");
  script_require_keys("installed_sw/JIRA Service Desk");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:"JIRA Service Desk", win_local:TRUE);

constraints = [
  { 'min_version' : '3.9.0', 'fixed_version' : '3.9.16' },
  { 'min_version' : '3.10.0', 'fixed_version' : '3.16.8' },
  { 'min_version' : '4.0.0', 'fixed_version' : '4.1.3' },
  { 'min_version' : '4.2.0', 'fixed_version' : '4.2.5' },
  { 'min_version' : '4.3.0', 'fixed_version' : '4.3.4' },
  { 'min_version' : '4.4.0', 'fixed_version' : '4.4.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
