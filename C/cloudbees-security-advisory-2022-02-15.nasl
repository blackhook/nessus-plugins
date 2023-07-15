#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158690);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2022-25173",
    "CVE-2022-25174",
    "CVE-2022-25175",
    "CVE-2022-25176",
    "CVE-2022-25177",
    "CVE-2022-25178",
    "CVE-2022-25179",
    "CVE-2022-25180",
    "CVE-2022-25181",
    "CVE-2022-25182",
    "CVE-2022-25183",
    "CVE-2022-25184",
    "CVE-2022-25185",
    "CVE-2022-25186",
    "CVE-2022-25187",
    "CVE-2022-25188",
    "CVE-2022-25189",
    "CVE-2022-25190",
    "CVE-2022-25191",
    "CVE-2022-25192",
    "CVE-2022-25193",
    "CVE-2022-25194",
    "CVE-2022-25195",
    "CVE-2022-25196",
    "CVE-2022-25197",
    "CVE-2022-25198",
    "CVE-2022-25199",
    "CVE-2022-25200",
    "CVE-2022-25201",
    "CVE-2022-25202",
    "CVE-2022-25203",
    "CVE-2022-25204",
    "CVE-2022-25205",
    "CVE-2022-25206",
    "CVE-2022-25207",
    "CVE-2022-25208",
    "CVE-2022-25209",
    "CVE-2022-25210",
    "CVE-2022-25211",
    "CVE-2022-25212"
  );

  script_name(english:"Jenkins Enterprise and Operations Center 2.277.x < 2.277.43.0.7 / 2.303.x < 2.303.30.0.6 / 2.319.3.4 Multiple Vulnerabilities (CloudBees Security Advisory 2022-02-15)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins Enterprise or Jenkins Operations Center running on the remote web server is 2.277.x prior to
2.277.43.0.7, 2.303.x prior to 2.303.30.0.6, or 2.x prior to 2.319.3.4. It is, therefore, affected by multiple
vulnerabilities, including the following:

  - Jenkins Pipeline: Groovy Plugin 2648.va9433432b33c and earlier uses the same checkout directories for
    distinct SCMs when reading the script file (typically Jenkinsfile) for Pipelines, allowing attackers with
    Item/Configure permission to invoke arbitrary OS commands on the controller through crafted SCM contents.
    (CVE-2022-25173)

  - Jenkins Pipeline: Shared Groovy Libraries Plugin 552.vd9cc05b8a2e1 and earlier uses the same checkout
    directories for distinct SCMs for Pipeline libraries, allowing attackers with Item/Configure permission to
    invoke arbitrary OS commands on the controller through crafted SCM contents. (CVE-2022-25174)

  - A sandbox bypass vulnerability in Jenkins Pipeline: Shared Groovy Libraries Plugin 552.vd9cc05b8a2e1 and
    earlier allows attackers with Item/Configure permission to execute arbitrary code on the Jenkins
    controller JVM using specially crafted library names if a global Pipeline library is already configured.
    (CVE-2022-25182)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.cloudbees.com/security-advisories/cloudbees-security-advisory-2022-02-15
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?646ce2df");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins Enterprise or Jenkins Operations Center to version 2.277.43.0.7, 2.303.30.0.6, 2.319.3.4, or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-25212");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/08");

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
  { 'min_version' : '2.277',  'fixed_version' : '2.277.43.0.7', 'edition' : make_list('Enterprise', 'Operations Center') },
  { 'min_version' : '2.303',  'fixed_version' : '2.303.30.0.6', 'edition' : make_list('Enterprise', 'Operations Center') },
  { 'min_version' : '2',      'fixed_version' : '2.319.3.4',    'edition' : make_list('Enterprise', 'Operations Center'), 'rolling_train' : TRUE },
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE, 'xsrf':TRUE}
);
