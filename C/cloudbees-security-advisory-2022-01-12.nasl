#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158059);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2022-20612",
    "CVE-2022-20613",
    "CVE-2022-20614",
    "CVE-2022-20615",
    "CVE-2022-20616",
    "CVE-2022-20617",
    "CVE-2022-20618",
    "CVE-2022-20619",
    "CVE-2022-20620",
    "CVE-2022-20621",
    "CVE-2022-23105",
    "CVE-2022-23106",
    "CVE-2022-23107",
    "CVE-2022-23108",
    "CVE-2022-23109",
    "CVE-2022-23110",
    "CVE-2022-23111",
    "CVE-2022-23112",
    "CVE-2022-23113",
    "CVE-2022-23114",
    "CVE-2022-23115",
    "CVE-2022-23116",
    "CVE-2022-23117",
    "CVE-2022-23118"
  );
  script_xref(name:"IAVA", value:"2022-A-0084");

  script_name(english:"Jenkins Enterprise and Operations Center < 2.277.43.0.5 / 2.319.2.5 Multiple Vulnerabilities (CloudBees Security Advisory 2022-01-12)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins Enterprise or Jenkins Operations Center running on the remote web server is 2.277.x prior to
2.277.43.0.5, or 2.x prior to 2.319.2.5. It is, therefore, affected by a multiple vulnerabilities, including the
following:

  - Jenkins Docker Commons Plugin 1.17 and earlier does not sanitize the name of an image or a tag, resulting
    in an OS command execution vulnerability exploitable by attackers with Item/Configure permission or able
    to control the contents of a previously configured job's SCM repository. (CVE-2022-20617)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Bitbucket Branch Source Plugin
    737.vdf9dc06105be and earlier allows attackers to connect to an attacker-specified URL using
    attacker-specified credentials IDs obtained through another method, capturing credentials stored in
    Jenkins. (CVE-2022-20619)

  - Jenkins Debian Package Builder Plugin 1.6.11 and earlier implements functionality that allows agents to
    invoke command-line `git` at an attacker-specified path on the controller, allowing attackers able to
    control agent processes to invoke arbitrary OS commands on the controller. (CVE-2022-23118)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.cloudbees.com/security-advisories/cloudbees-security-advisory-2022-01-12
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92a04731");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins Enterprise or Jenkins Operations Center to version 2.277.43.0.5, 2.319.2.5, or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23118");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'min_version' : '2.277',  'fixed_version' : '2.277.43.0.5', 'edition' : make_list('Enterprise', 'Operations Center') },
  { 'min_version' : '2',      'fixed_version' : '2.319.2.5',    'edition' : make_list('Enterprise', 'Operations Center'), 'rolling_train' : TRUE },
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{'xss':TRUE, 'xsrf':TRUE}
);
