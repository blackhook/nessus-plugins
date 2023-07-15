#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153890);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2021-21677",
    "CVE-2021-21678",
    "CVE-2021-21679",
    "CVE-2021-21680",
    "CVE-2021-21681"
  );

  script_name(english:"Jenkins Enterprise and Operations Center < 2.249.32.0.2 / 2.277.41.0.2 / 2.303.1.6 Multiple Vulnerabilities (CloudBees Security Advisory 2021-08-31)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins Enterprise or Jenkins Operations Center running on the remote web server is 2.x prior to
2.303.1.6, 2.249.x prior to 2.249.32.0.2, or 2.277.x prior to 2.277.41.0.2. It is, therefore, affected by multiple
vulnerabilities, including the following:

  - Jenkins Code Coverage API Plugin 1.4.0 and earlier does not apply Jenkins JEP-200 deserialization
    protection to Java objects it deserializes from disk, resulting in a remote code execution vulnerability.
    (CVE-2021-21677)

  - Jenkins SAML Plugin 2.0.7 and earlier allows attackers to craft URLs that would bypass the CSRF protection
    of any target URL in Jenkins. (CVE-2021-21678)

  - Jenkins Azure AD Plugin 179.vf6841393099e and earlier allows attackers to craft URLs that would bypass the
    CSRF protection of any target URL in Jenkins. (CVE-2021-21679)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cloudbees.com/cloudbees-security-advisory-2021-08-31");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins Enterprise or Jenkins Operations Center to version 2.249.32.0.2, 2.277.41.0.2, 2.303.1.6 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21679");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/06");

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
  { 'min_version' : '2.249',  'fixed_version' : '2.249.32.0.2', 'edition' : make_list('Enterprise', 'Operations Center') },
  { 'min_version' : '2.277',  'fixed_version' : '2.277.41.0.2', 'edition' : make_list('Enterprise', 'Operations Center') },
  { 'min_version' : '2',      'fixed_version' : '2.303.1.6',    'edition' : make_list('Enterprise', 'Operations Center'), 'rolling_train' : TRUE }
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xsrf':TRUE}
);
