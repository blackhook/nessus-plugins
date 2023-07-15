#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc. 
##

include('compat.inc');

if (description)
{
  script_id(164431);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/03");

  script_cve_id("CVE-2022-2884");
  script_xref(name:"IAVA", value:"2022-A-0341-S");

  script_name(english:"GitLab 11.3.4 < 15.1.5 / 15.2 < 15.2.3 / 15.3 < 15.3.1 RCE");

  script_set_attribute(attribute:"synopsis", value:
"A source control application running on the remote web server is affected by an RCE vulnerability.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in GitLab CE/EE affecting all versions starting from 11.3.4 before 15.1.5, all versions
starting from 15.2 before 15.2.3, all versions starting from 15.3 before 15.3.1 allows an an authenticated
user to achieve remote code execution via the Import from GitHub API endpoint.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2022/08/22/critical-security-release-gitlab-15-3-1-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9134ba39");
  script_set_attribute(attribute:"solution", value:
"Upgrade to GitLab version 15.1.5, 15.2.3, 15.3.1 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2884");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gitlab:gitlab");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("gitlab_webui_detect.nbin", "gitlab_nix_installed.nbin");
  script_require_keys("installed_sw/GitLab");

  exit(0);
}

include('vcf.inc');

var app = 'GitLab';

var app_info = vcf::combined_get_app_info(app:app);

# Remote detection can only get the first two segments. requires paranoia for 15.1/2/3 checks
if (report_paranoia < 2 && max_index(app_info.parsed_version[0]) < 3 && app_info.version =~ "15\.(1|2|3)([^0-9]|$)")
  audit(AUDIT_POTENTIAL_VULN, app, app_info.version, app_info.port);

var constraints = [
  { 'min_version': '11.3.4', 'fixed_version': '15.1.5'},
  { 'min_version': '15.2', 'fixed_version': '15.2.3'},
  { 'min_version': '15.3', 'fixed_version': '15.3.1'}
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
