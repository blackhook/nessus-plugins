#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167634);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/17");

  script_cve_id(
    "CVE-2022-33980",
    "CVE-2022-38666",
    "CVE-2022-45379",
    "CVE-2022-45380",
    "CVE-2022-45381",
    "CVE-2022-45382",
    "CVE-2022-45383",
    "CVE-2022-45384",
    "CVE-2022-45385",
    "CVE-2022-45386",
    "CVE-2022-45387",
    "CVE-2022-45388",
    "CVE-2022-45389",
    "CVE-2022-45390",
    "CVE-2022-45391",
    "CVE-2022-45392",
    "CVE-2022-45393",
    "CVE-2022-45394",
    "CVE-2022-45395",
    "CVE-2022-45396",
    "CVE-2022-45397",
    "CVE-2022-45398",
    "CVE-2022-45399",
    "CVE-2022-45400",
    "CVE-2022-45401"
  );

  script_name(english:"Jenkins Enterprise and Operations Center 2.346.x < 2.346.40.0.6 / 2.361.3.4 Multiple Vulnerabilities (CloudBees Security Advisory 2022-11-15)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins Enterprise or Jenkins Operations Center running on the remote web server is 2.346.x prior to
2.346.40.0.6 or 2.x prior to 2.361.3.4. It is, therefore, affected by multiple vulnerabilities including the following:

  - CVE-2022-38751 on snakeyaml (fixed train 2.346.x.0.z) (BEE-23728)

  - CVE-2022-38749 on snakeyaml (fixed train 2.346.x.0.z) (BEE-23729)

  - Remote code execution vulnerability in Pipeline Utility Steps Plugin (CVE-2022-33980)

  - SSL/TLS certificate validation unconditionally disabled by NS-ND Integration Performance Publisher Plugin
    (CVE-2022-38666)

  - Whole-script approval in Script Security Plugin vulnerable to SHA-1 collisions (CVE-2022-45379)

  - Stored XSS vulnerability in JUnit Plugin (CVE-2022-45380)

  - Arbitrary file read vulnerability in Pipeline Utility Steps Plugin (CVE-2022-45381)

  - Stored XSS vulnerability in Naginator Plugin (CVE-2022-45382)

  - Incorrect permission checks in Support Core Plugin (CVE-2022-45383)

  - Password stored in plain text by Reverse Proxy Auth Plugin (CVE-2022-45384)

  - Lack of authentication mechanism for webhook in CloudBees Docker Hub/Registry Notification Plugin
    (CVE-2022-45385)

  - XXE vulnerability on agents in Violations Plugin (CVE-2022-45386)

  - Stored XSS vulnerability in BART Plugin (CVE-2022-45387)

  - Arbitrary file read vulnerability in Config Rotator Plugin (CVE-2022-45388)

  - Lack of authentication mechanism for webhook in XP-Dev Plugin (CVE-2022-45389)

  - Missing permission check in loader.io Plugin allows enumerating credentials IDs (CVE-2022-45390)

  - SSL/TLS certificate validation globally and unconditionally disabled by NS-ND Integration Performance
    Publisher Plugin (CVE-2022-45391)

  - Passwords stored in plain text by NS-ND Integration Performance Publisher Plugin (CVE-2022-45392)

  - CSRF vulnerability and missing permission check in Delete log Plugin (CVE-2022-45393, CVE-2022-45394)

  - XXE vulnerability on agents in CCCC Plugin (CVE-2022-45395)

  - XXE vulnerability on agents in SourceMonitor Plugin (CVE-2022-45396)

  - XXE vulnerability on agents in OSF Builder Suite :: XML Linter Plugin (CVE-2022-45397)

  - CSRF vulnerability and missing permission check in Cluster Statistics Plugin (CVE-2022-45398,
    CVE-2022-45399)

  - XXE vulnerability in JAPEX Plugin (CVE-2022-45400)

  - Stored XSS vulnerability in Associated Files Plugin (CVE-2022-45401)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.cloudbees.com/security-advisories/cloudbees-security-advisory-2022-11-15
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9523d7d");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins Enterprise or Jenkins Operations Center to version 2.346.40.0.6, 2.361.3.4 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-33980");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'fixed_version' :'2.346.40.0.6',
    'edition' : make_list('Enterprise', 'Operations Center')
  },
  {
    'min_version' : '2',
    'fixed_version' :'2.361.3.4',
    'edition' : make_list('Enterprise', 'Operations Center'),
    'rolling_train' : TRUE
  }
];

vcf::jenkins::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE, 'xss':TRUE}
);
