##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161441);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/24");

  script_cve_id(
    "CVE-2022-27195",
    "CVE-2022-27196",
    "CVE-2022-27197",
    "CVE-2022-27198",
    "CVE-2022-27199",
    "CVE-2022-27200",
    "CVE-2022-27201",
    "CVE-2022-27202",
    "CVE-2022-27203",
    "CVE-2022-27204",
    "CVE-2022-27205",
    "CVE-2022-27206",
    "CVE-2022-27207",
    "CVE-2022-27208",
    "CVE-2022-27209",
    "CVE-2022-27210",
    "CVE-2022-27211",
    "CVE-2022-27212",
    "CVE-2022-27213",
    "CVE-2022-27214",
    "CVE-2022-27215",
    "CVE-2022-27216",
    "CVE-2022-27217",
    "CVE-2022-27218"
  );

  script_name(english:"Jenkins Enterprise and Operations Center 2.277.x < 2.277.43.0.8 / 2.303.x < 2.303.30.0.7 / 2.332.1.5 Multiple Vulnerabilities (CloudBees Security Advisory 2022-03-15)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins Enterprise or Jenkins Operations Center running on the remote web server is 2.277.x prior to
2.277.43.0.8, 2.303.x prior to 2.303.30.0.7, or 2.x prior to 2.332.1.5. It is, therefore, affected by multiple
vulnerabilities, including the following:

  - A cross-site request forgery (CSRF) vulnerability in Jenkins CloudBees AWS Credentials Plugin
    189.v3551d5642995 and earlier allows attackers with Overall/Read permission to connect to an AWS service
    using an attacker-specified token. (CVE-2022-27198)

  - Jenkins Semantic Versioning Plugin 1.13 and earlier does not restrict execution of an controller/agent
    message to agents, and implements no limitations about the file path that can be parsed, allowing
    attackers able to control agent processes to have Jenkins parse a crafted file that uses external entities
    for extraction of secrets from the Jenkins controller or server-side request forgery. (CVE-2022-27201)

  - A cross-site request forgery vulnerability in Jenkins Extended Choice Parameter Plugin 346.vd87693c5a_86c
    and earlier allows attackers to connect to an attacker-specified URL. (CVE-2022-27204)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.cloudbees.com/security-advisories/cloudbees-security-advisory-2022-03-15
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0df89c30");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins Enterprise or Jenkins Operations Center to version 2.277.43.0.8, 2.303.30.0.7, 2.332.1.5, or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27204");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/23");

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
  { 'min_version' : '2.277',  'fixed_version' : '2.277.43.0.8', 'edition' : make_list('Enterprise', 'Operations Center') },
  { 'min_version' : '2.303',  'fixed_version' : '2.303.30.0.7', 'edition' : make_list('Enterprise', 'Operations Center') },
  { 'min_version' : '2',      'fixed_version' : '2.332.1.5',    'edition' : make_list('Enterprise', 'Operations Center'), 'rolling_train' : TRUE },
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE, 'xsrf':TRUE}
);
