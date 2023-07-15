##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162722);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/06");

  script_cve_id(
    "CVE-2022-34170",
    "CVE-2022-34171",
    "CVE-2022-34172",
    "CVE-2022-34173",
    "CVE-2022-34174",
    "CVE-2022-34175",
    "CVE-2022-34176",
    "CVE-2022-34177",
    "CVE-2022-34178",
    "CVE-2022-34179",
    "CVE-2022-34180",
    "CVE-2022-34181",
    "CVE-2022-34182",
    "CVE-2022-34183",
    "CVE-2022-34184",
    "CVE-2022-34185",
    "CVE-2022-34186",
    "CVE-2022-34187",
    "CVE-2022-34188",
    "CVE-2022-34189",
    "CVE-2022-34190",
    "CVE-2022-34191",
    "CVE-2022-34192",
    "CVE-2022-34193",
    "CVE-2022-34194",
    "CVE-2022-34195",
    "CVE-2022-34196",
    "CVE-2022-34197",
    "CVE-2022-34198",
    "CVE-2022-34199",
    "CVE-2022-34200",
    "CVE-2022-34201",
    "CVE-2022-34202",
    "CVE-2022-34203",
    "CVE-2022-34204",
    "CVE-2022-34205",
    "CVE-2022-34206",
    "CVE-2022-34207",
    "CVE-2022-34208",
    "CVE-2022-34209",
    "CVE-2022-34210",
    "CVE-2022-34211",
    "CVE-2022-34212",
    "CVE-2022-34213"
  );

  script_name(english:"Jenkins Enterprise and Operations Center 2.303.x < 2.303.30.0.14 / 2.332.4.1 / 2.346.1.4 Multiple Vulnerabilities (CloudBees Security Advisory 2022-06-22)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins Enterprise or Jenkins Operations Center running on the remote web server is 2.303.x prior to
2.303.30.0.14, or 2.x prior to 2.332.4.1 or 2.346.1.4. It is, therefore, affected by multiple vulnerabilities, including
the following:

  - Jenkins Pipeline: Input Step Plugin 448.v37cea_9a_10a_70 and earlier archives files uploaded for `file`
    parameters for Pipeline `input` steps on the controller as part of build metadata, using the parameter
    name without sanitization as a relative path inside a build-related directory, allowing attackers able to
    configure Pipelines to create or replace arbitrary files on the Jenkins controller file system with
    attacker-specified content. (CVE-2022-34177)

  - Jenkins xUnit Plugin 3.0.8 and earlier implements an agent-to-controller message that creates a
    user-specified directory if it doesn't exist, and parsing files inside it as test results, allowing
    attackers able to control agent processes to create an arbitrary directory on the Jenkins controller or to
    obtain test results from existing files in an attacker-specified directory. (CVE-2022-34181)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins EasyQA Plugin 1.0 and earlier allows
    attackers to connect to an attacker-specified HTTP server. (CVE-2022-34203)
  
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.cloudbees.com/security-advisories/cloudbees-security-advisory-2022-06-22
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32de3d70");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins Enterprise or Jenkins Operations Center to version 2.303.30.0.14, 2.332.4.1, 2.346.1.4 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34203");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-34181");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/05");

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
  { 'min_version' : '2.303', 'fixed_version' : '2.303.30.0.14', 'edition' : make_list('Enterprise', 'Operations Center') },
  { 'min_version' : '2', 'fixed_version' : '2.332.4.1', 'fixed_display' : '2.332.4.1 / 2.346.1.4', 'edition' : make_list('Enterprise', 'Operations Center'), 'rolling_train' : TRUE },
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE, 'xsrf':TRUE}
);
