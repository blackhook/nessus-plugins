#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170980);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id("CVE-2023-22501");
  script_xref(name:"IAVA", value:"2023-A-0066-S");

  script_name(english:"Atlassian JIRA Service Desk 5.3.x < 5.3.3 / 5.4.x < 5.4.2 / 5.5.x < 5.5.1 Impersonation (JSDSERVER-12312)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by an authentication vulnerability.");
  script_set_attribute(attribute:"description", value:
"The instance of  Atlassian Service Desk hosted on the remote web server is 5.3 prior to 5.3.3, 5.4 prior to 5.4.2 or
5.5 prior to 5.5.1. Is is, therefore, affected by an authentication vulnerability. A remote attacker included on Jira
issues or requests with other users can impersonate those users if they are forwarded or otherwise gain access to
emails containing a 'View Request' link from one of those users.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JSDSERVER-12312");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian JIRA Service Desk Server 5.3.3 / 5.4.2 / 5.5.1 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22501");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira_service_desk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "jira_service_desk_installed_win.nbin", "jira_service_desk_installed_nix.nbin");
  script_require_keys("installed_sw/JIRA Service Desk Application");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'JIRA Service Desk Application');


var constraints = [
  { 'min_version' : '5.3.0', 'fixed_version' : '5.3.3' },
  { 'min_version' : '5.4.0', 'fixed_version' : '5.4.2' },
  { 'min_version' : '5.5.0', 'fixed_version' : '5.5.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
