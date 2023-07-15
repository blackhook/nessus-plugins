#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171788);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/22");

  script_name(english:"Atlassian Jira < 9.0.0 Information Disclosure (JRASERVER-73926)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Jira host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Jira Server running on the remote host is affected by an information disclosure vulnerability
as referenced in the JRASERVER-73926 advisory, which can be exploited by an unauthenticated attacker.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-73926");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira version 9.0.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Information Disclosure Score");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl", "atlassian_jira_win_installed.nbin", "atlassian_jira_nix_installed.nbin");
  script_require_keys("installed_sw/Atlassian JIRA");

  exit(0);
}

include('vcf.inc');
var app_info = vcf::combined_get_app_info(app:'Atlassian JIRA');

var constraints = [
  { 'fixed_version' : '9.0.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
