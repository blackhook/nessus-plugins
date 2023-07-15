#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165764);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/01");

  script_cve_id(
    "CVE-2022-36881",
    "CVE-2022-36882",
    "CVE-2022-36883",
    "CVE-2022-36884",
    "CVE-2022-36885",
    "CVE-2022-36886",
    "CVE-2022-36887",
    "CVE-2022-36888",
    "CVE-2022-36889",
    "CVE-2022-36890",
    "CVE-2022-36891",
    "CVE-2022-36892",
    "CVE-2022-36893",
    "CVE-2022-36894",
    "CVE-2022-36895",
    "CVE-2022-36896",
    "CVE-2022-36897",
    "CVE-2022-36898",
    "CVE-2022-36899",
    "CVE-2022-36900",
    "CVE-2022-36901",
    "CVE-2022-36902",
    "CVE-2022-36903",
    "CVE-2022-36904",
    "CVE-2022-36905",
    "CVE-2022-36906",
    "CVE-2022-36907",
    "CVE-2022-36908",
    "CVE-2022-36909",
    "CVE-2022-36910",
    "CVE-2022-36911",
    "CVE-2022-36912",
    "CVE-2022-36913",
    "CVE-2022-36914",
    "CVE-2022-36915",
    "CVE-2022-36916",
    "CVE-2022-36917",
    "CVE-2022-36918",
    "CVE-2022-36919",
    "CVE-2022-36920",
    "CVE-2022-36921",
    "CVE-2022-36922"
  );

  script_name(english:"Jenkins Enterprise and Operations Center 2.303.x < 2.303.30.0.15 / 2.346.2.3 Multiple Vulnerabilities (CloudBees Security Advisory 2022-07-27)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins Enterprise or Jenkins Operations Center running on the remote web server is 2.303.x prior to
2.303.30.0.15, or 2.x prior to 2.346.2.3. It is, therefore, affected by multiple vulnerabilities, including the
following:

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Git Plugin 4.11.3 and earlier allows
    attackers to trigger builds of jobs configured to use an attacker-specified Git repository and to cause
    them to check out an attacker-specified commit. (CVE-2022-36882)

  - Jenkins Deployer Framework Plugin 85.v1d1888e8c021 and earlier does not restrict the application path of
    the applications when configuring a deployment, allowing attackers with Item/Configure permission to
    upload arbitrary files from the Jenkins controller file system to the selected service. (CVE-2022-36889)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Coverity Plugin 1.11.4 and earlier allows
    attackers to connect to an attacker-specified URL using attacker-specified credentials IDs obtained
    through another method, capturing credentials stored in Jenkins. (CVE-2022-36920)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.cloudbees.com/security-advisories/cloudbees-security-advisory-2022-07-27
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?112060fa");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins Enterprise or Jenkins Operations Center to version 2.303.30.0.15, 2.346.2.3 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-36920");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/07");

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
  { 'min_version' : '2.303', 'fixed_version' : '2.303.30.0.15', 'edition' : make_list('Enterprise', 'Operations Center') },
  { 'min_version' : '2',     'fixed_version' : '2.346.2.3',     'edition' : make_list('Enterprise', 'Operations Center'), 'rolling_train' : TRUE },
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{'xss':TRUE, 'xsrf':TRUE}
);
