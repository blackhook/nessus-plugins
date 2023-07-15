#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153976);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Jenkins Enterprise and Operations Center < 2.249.31.0.5 / 2.289.1.2 Multiple Vulnerabilities (CloudBees Security Advisory 2021-06-02)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins Enterprise or Jenkins Operations Center running on the remote web server is 2.249.x prior to
2.249.31.0.5, or 2.x prior to 2.289.1.2. It is, therefore, affected by multiple vulnerabilities, including the
following:

  - A flaw exists in CloudBees Jenkins due to RBAC role definitions being pushed to connected clients, even
    when RBAC is not being used. (BEE-177)

  - A cross-site request forgery vulnerability exists in the CloudBees Assurance Plugin due to the plugin not
    requiring POST requests for the form submission endpoint configuring the update center. An
    unauthenticated, remote attacker can exploit this, via the HTTP endpoint, allowing attackers to configure
    the default update center. (BEE-2047)

  - A flaw exists in the BasicDefaultsProvider due to providing invalid roles to the default configuration.
    (BEE-3042)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cloudbees.com/cloudbees-security-advisory-2021-06-02");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins Enterprise or Jenkins Operations Center to version 2.249.31.0.5, 2.289.1.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/11");

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
  { 'min_version' : '2.249',  'fixed_version' : '2.249.31.0.5', 'edition' : 'Enterprise' },
  { 'min_version' : '2',      'fixed_version' : '2.289.1.2',    'edition' : 'Enterprise', 'rolling_train' : TRUE },
  { 'min_version' : '2.249',  'fixed_version' : '2.249.31.0.5', 'edition' : 'Operations Center' },
  { 'min_version' : '2',      'fixed_version' : '2.289.1.2',    'edition' : 'Operations Center', 'rolling_train' : TRUE }
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xsrf':TRUE}
);
