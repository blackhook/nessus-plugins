##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163657);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/01");

  script_name(english:"Atlassian Jira < 8.13.20 / 8.20.x < 8.20.8 / 8.22.x < 8.22.2 / 9.0.x < 9.0.0 (JRASERVER-73739)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Jira host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Jira Server running on the remote host is affected by a vulnerability as referenced in the
JRASERVER-73739 advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-73739");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira version 8.13.20, 8.20.8, 8.22.2, 9.0.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl", "atlassian_jira_win_installed.nbin", "atlassian_jira_nix_installed.nbin");
  script_require_keys("installed_sw/Atlassian JIRA");

  exit(0);
}

include('vcf.inc');
var app_info = vcf::combined_get_app_info(app:'Atlassian JIRA');

var constraints = [
  { 'fixed_version' : '8.13.20', 'fixed_display' : '8.13.20 / 8.20.8 / 8.22.2 / 9.0.0' },
  { 'min_version' : '8.20.7', 'fixed_version' : '8.20.8' },
  { 'min_version' : '8.22.1', 'fixed_version' : '8.22.2' },
  { 'min_version' : '8.23.0', 'fixed_version' : '9.0.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
