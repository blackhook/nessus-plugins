#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152137);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-36239");
  script_xref(name:"IAVA", value:"2021-A-0354");

  script_name(english:"Atlassian Jira Data Center / Jira Service Management Data Center Missing Authentication (2021-07-21)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a missing authentication vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Atlassian Jira hosted on the remote web server is
affected by a missing authentication flaw in its Ehcache RMI component. An unauthenticated, remote attacker could 
exploit this to bypass authentication and execute arbitrary code on an affected system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://confluence.atlassian.com/adminjiraserver/jira-data-center-and-jira-service-management-data-center-security-advisory-2021-07-21-1063571388.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c7a7aa0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira Data Center / Jira Service Management 
  Data Center to version 4.5.16, 4.13.8, 4.17.0, 8.5.16, 8.13.8, 8.17.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36239");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl", "atlassian_jira_win_installed.nbin", "atlassian_jira_nix_installed.nbin");
  script_require_keys("installed_sw/Atlassian JIRA");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Atlassian JIRA');
var edition = app_info['Edition'];

if (edition == 'Unknown' || edition != 'Jira Data Center')
  audit(AUDIT_HOST_NOT, 'an affected Jira edition');

var constraints = [
  {'min_version':'2.0.2', 'fixed_version':'4.5.16'},
  {'min_version':'4.6.0', 'fixed_version':'4.13.8'},
  {'min_version':'4.14.0', 'fixed_version':'4.17.0'},
  {'min_version':'6.3.0', 'fixed_version':'8.5.16'},
  {'min_version':'8.6.0', 'fixed_version':'8.13.8'},
  {'min_version':'8.14.0', 'fixed_version':'8.17.0'}
];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_HOLE
);
