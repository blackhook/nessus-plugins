#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173922);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/05");

  script_name(english:"Jenkins Enterprise and Operations Center 2.346.x < 2.346.40.0.14 Multiple Vulnerabilities (CloudBees Security Advisory 2023-04-05)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins Enterprise or Jenkins Operations Center running on the remote web server is 2.346.x prior to
2.346.40.0.14. It is, therefore, affected by multiple vulnerabilities including the following:

  - CloudBees Backup plugin uses SHA-1 hashes for the approvers map (BEE-29578)

  - CloudBees Pipeline: Template used insecure SnakeYaml constructor (BEE-30448)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.cloudbees.com/security-advisories/cloudbees-security-advisory-2023-04-05
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e8a06bc");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins Enterprise or Jenkins Operations Center to version 2.346.40.0.14 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Jenkins');

var constraints = [
  {
    'min_version' : '2.346',
    'fixed_version' :'2.346.40.0.14',
    'edition' : make_list('Enterprise', 'Operations Center')
  }
];

vcf::jenkins::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
