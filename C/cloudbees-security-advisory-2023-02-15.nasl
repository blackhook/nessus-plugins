#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171501);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/27");

  script_cve_id(
    "CVE-2023-23847",
    "CVE-2023-23848",
    "CVE-2023-23850",
    "CVE-2023-25761",
    "CVE-2023-25762",
    "CVE-2023-25763",
    "CVE-2023-25764",
    "CVE-2023-25765",
    "CVE-2023-25766",
    "CVE-2023-25767",
    "CVE-2023-25768"
  );

  script_name(english:"Jenkins Enterprise and Operations Center 2.346.x < 2.346.40.0.9 Multiple Vulnerabilities (CloudBees Security Advisory 2023-02-15)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins Enterprise or Jenkins Operations Center running on the remote web server is 2.346.x prior to
2.346.40.0.9. It is, therefore, affected by multiple vulnerabilities including the following:

  - CSRF vulnerability and missing permission checks in Synopsys Coverity Plugin allow capturing credentials
    (CVE-2023-23847, CVE-2023-23848)

  - Missing permission checks in Synopsys Coverity Plugin allow enumerating credentials IDs (CVE-2023-23850)

  - Stored XSS vulnerability in JUnit Plugin (CVE-2023-25761)

  - Stored XSS vulnerability in Pipeline: Build Step Plugin (CVE-2023-25762)

  - XSS vulnerability in bundled email templates in Email Extension Plugin (CVE-2023-25763)

  - Stored XSS vulnerability in custom email templates in Email Extension Plugin (CVE-2023-25764)

  - Script Security sandbox bypass vulnerability in Email Extension Plugin (CVE-2023-25765)

  - Missing permission checks in Azure Credentials Plugin allow enumerating credentials IDs (CVE-2023-25766)

  - CSRF vulnerability and missing permission checks in Azure Credentials Plugin (CVE-2023-25767,
    CVE-2023-25768)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.cloudbees.com/security-advisories/cloudbees-security-advisory-2023-02-15
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1b4c133");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins Enterprise or Jenkins Operations Center to version 2.346.40.0.9 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25767");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/15");

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
    'fixed_version' :'2.346.40.0.9',
    'edition' : make_list('Enterprise', 'Operations Center')
  }
];

vcf::jenkins::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE, 'xss':TRUE}
);
