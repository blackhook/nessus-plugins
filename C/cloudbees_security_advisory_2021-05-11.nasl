#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154965);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-21648",
    "CVE-2021-21649",
    "CVE-2021-21650",
    "CVE-2021-21651",
    "CVE-2021-21652",
    "CVE-2021-21653",
    "CVE-2021-21654",
    "CVE-2021-21655",
    "CVE-2021-21656"
  );

  script_name(english:"Jenkins Enterprise and Operations Center < 2.249.31.0.4 / 2.277.4.3 Multiple Vulnerabilities (CloudBees Security Advisory 2021-05-11)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins Enterprise or Jenkins Operations Center running on the remote web server is 2.249.x prior to
2.249.31.0.4, or 2.x prior to 2.277.4.3. It is, therefore, affected by multiple vulnerabilities, including the
following:

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Xray - Test Management for Jira Plugin 2.4.0
    and earlier allows attackers to connect to an attacker-specified URL using attacker-specified credentials
    IDs obtained through another method, capturing credentials stored in Jenkins. (CVE-2021-21652)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins P4 Plugin 1.11.4 and earlier allows attackers
    to connect to an attacker-specified Perforce server using attacker-specified username and password.
    (CVE-2021-21655)

  - Jenkins Xcode integration Plugin 2.0.14 and earlier does not configure its XML parser to prevent XML
    external entity (XXE) attacks. (CVE-2021-21656)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cloudbees.com/cloudbees-security-advisory-2021-05-11");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins Enterprise or Jenkins Operations Center to version 2.249.31.0.4, 2.277.4.3 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21655");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21656");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Jenkins');

var constraints = [
  { 'min_version' : '2.249',  'fixed_version' : '2.249.31.0.4', 'edition' : make_list('Enterprise', 'Operations Center') },
  { 'min_version' : '2',      'fixed_version' : '2.277.4.3',    'edition' : make_list('Enterprise', 'Operations Center'), 'rolling_train' : TRUE }
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xsrf':TRUE, 'xss':TRUE}
);
