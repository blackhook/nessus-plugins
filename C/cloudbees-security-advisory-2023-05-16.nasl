#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175835);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/12");

  script_cve_id(
    "CVE-2023-2195",
    "CVE-2023-2196",
    "CVE-2023-2631",
    "CVE-2023-2632",
    "CVE-2023-2633",
    "CVE-2023-32977",
    "CVE-2023-32978",
    "CVE-2023-32979",
    "CVE-2023-32980",
    "CVE-2023-32981",
    "CVE-2023-32982",
    "CVE-2023-32983",
    "CVE-2023-32984",
    "CVE-2023-32985",
    "CVE-2023-32986",
    "CVE-2023-32987",
    "CVE-2023-32988",
    "CVE-2023-32989",
    "CVE-2023-32990",
    "CVE-2023-32991",
    "CVE-2023-32992",
    "CVE-2023-32993",
    "CVE-2023-32994",
    "CVE-2023-32995",
    "CVE-2023-32996",
    "CVE-2023-32997",
    "CVE-2023-32998",
    "CVE-2023-32999",
    "CVE-2023-33000",
    "CVE-2023-33001",
    "CVE-2023-33002",
    "CVE-2023-33003",
    "CVE-2023-33004",
    "CVE-2023-33005",
    "CVE-2023-33006",
    "CVE-2023-33007"
  );

  script_name(english:"Jenkins Enterprise and Operations Center 2.346.x < 2.346.40.0.17 Multiple Vulnerabilities (CloudBees Security Advisory 2023-05-16)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins Enterprise or Jenkins Operations Center running on the remote web server is 2.346.x prior to
2.346.40.0.17. It is, therefore, affected by multiple vulnerabilities including the following:

  - CSRF vulnerability and missing permission checks in Code Dx Plugin (CVE-2023-2195, CVE-2023-2631)

  - Missing permission checks in Code Dx Plugin (CVE-2023-2196)

  - API keys stored and displayed in plain text by Code Dx Plugin (CVE-2023-2632, CVE-2023-2633)

  - Stored XSS vulnerability in Pipeline: Job Plugin (CVE-2023-32977)

  - CSRF vulnerability in LDAP Plugin (CVE-2023-32978)

  - Missing permission check in Email Extension Plugin (CVE-2023-32979)

  - CSRF vulnerability in Email Extension Plugin (CVE-2023-32980)

  - Arbitrary file write vulnerability on agents in Pipeline Utility Steps Plugin (CVE-2023-32981)

  - Secrets stored and displayed in plain text by Ansible Plugin (CVE-2023-32982, CVE-2023-32983)

  - Stored XSS vulnerability in TestNG Results Plugin (CVE-2023-32984)

  - Path traversal vulnerability in Sidebar Link Plugin (CVE-2023-32985)

  - Arbitrary file write vulnerability in File Parameter Plugin (CVE-2023-32986)

  - CSRF vulnerability in Reverse Proxy Auth Plugin (CVE-2023-32987)

  - Missing permission check in Azure VM Agents Plugin allows enumerating credentials IDs (CVE-2023-32988)

  - CSRF vulnerability and missing permission checks in Azure VM Agents Plugin (CVE-2023-32989,
    CVE-2023-32990)

  - CSRF vulnerability and missing permission checks in SAML Single Sign On(SSO) Plugin allow XXE
    (CVE-2023-32991, CVE-2023-32992)

  - Missing hostname validation in SAML Single Sign On(SSO) Plugin (CVE-2023-32993)

  - SSL/TLS certificate validation unconditionally disabled by SAML Single Sign On(SSO) Plugin
    (CVE-2023-32994)

  - CSRF vulnerability and missing permission check in SAML Single Sign On(SSO) Plugin (CVE-2023-32995,
    CVE-2023-32996)

  - Session fixation vulnerability in CAS Plugin (CVE-2023-32997)

  - CSRF vulnerability and missing permission check in AppSpider Plugin (CVE-2023-32998, CVE-2023-32999)

  - Credentials displayed without masking by NS-ND Integration Performance Publisher Plugin (CVE-2023-33000)

  - Improper masking of credentials in HashiCorp Vault Plugin (CVE-2023-33001)

  - Stored XSS vulnerability in TestComplete support Plugin (CVE-2023-33002)

  - CSRF vulnerability and missing permission checks in Tag Profiler Plugin (CVE-2023-33003, CVE-2023-33004)

  - Session fixation vulnerability in WSO2 Oauth Plugin (CVE-2023-33005)

  - CSRF vulnerability in WSO2 Oauth Plugin (CVE-2023-33006)

  - Stored XSS vulnerability in LoadComplete support Plugin (CVE-2023-33007)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.cloudbees.com/security-advisories/cloudbees-security-advisory-2023-05-16
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee6e52d7");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins Enterprise or Jenkins Operations Center to version 2.346.40.0.17 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32998");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/16");

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
    'fixed_version' :'2.346.40.0.17',
    'edition' : make_list('Enterprise', 'Operations Center')
  }
];

vcf::jenkins::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE, 'xss':TRUE}
);
