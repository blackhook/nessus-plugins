#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155715);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2021-21602",
    "CVE-2021-21603",
    "CVE-2021-21604",
    "CVE-2021-21605",
    "CVE-2021-21606",
    "CVE-2021-21607",
    "CVE-2021-21608",
    "CVE-2021-21609",
    "CVE-2021-21610",
    "CVE-2021-21611",
    "CVE-2021-21612",
    "CVE-2021-21613",
    "CVE-2021-21614"
  );

  script_name(english:"Jenkins Enterprise and Operations Center < 2.222.43.0.1 / 2.249.30.0.1 / 2.263.2.2 Multiple Vulnerabilities (CloudBees Security Advisory 2021-01-13)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins Enterprise or Jenkins Operations Center running on the remote web server is 2.222.x prior to
2.222.43.0.1, 2.249.x prior to 2.249.30.0.1, or 2.x prior to 2.263.2.2. It is, therefore, affected by multiple
vulnerabilities, including the following:

  - Jenkins 2.274 and earlier, LTS 2.263.1 and earlier allows attackers with permission to create or configure
    various objects to inject crafted content into Old Data Monitor that results in the instantiation of
    potentially unsafe objects once discarded by an administrator. (CVE-2021-21604)

  - Jenkins 2.274 and earlier, LTS 2.263.1 and earlier allows users with Agent/Configure permission to choose
    agent names that cause Jenkins to override the global `config.xml` file. (CVE-2021-21605)

  - Jenkins 2.274 and earlier, LTS 2.263.1 and earlier does not correctly match requested URLs to the list of
    always accessible paths, allowing attackers without Overall/Read permission to access some URLs as if they
    did have Overall/Read permission. (CVE-2021-21609)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cloudbees.com/cloudbees-security-advisory-2021-01-13");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins Enterprise or Jenkins Operations Center to version 2.222.43.0.1, 2.249.30.0.1, 2.263.2.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21605");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/29");

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
  { 'min_version' : '2.222',  'fixed_version' : '2.222.43.0.1', 'edition' : make_list('Enterprise', 'Operations Center') },
  { 'min_version' : '2.249',  'fixed_version' : '2.249.30.0.1', 'edition' : make_list('Enterprise', 'Operations Center') },
  { 'min_version' : '2',      'fixed_version' : '2.263.2.2',    'edition' : make_list('Enterprise', 'Operations Center'), 'rolling_train' : TRUE },
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
