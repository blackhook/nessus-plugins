##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161210);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2022-29036",
    "CVE-2022-29037",
    "CVE-2022-29038",
    "CVE-2022-29039",
    "CVE-2022-29040",
    "CVE-2022-29041",
    "CVE-2022-29042",
    "CVE-2022-29043",
    "CVE-2022-29044",
    "CVE-2022-29045",
    "CVE-2022-29046",
    "CVE-2022-29047",
    "CVE-2022-29048",
    "CVE-2022-29049",
    "CVE-2022-29050",
    "CVE-2022-29051",
    "CVE-2022-29052"
  );

  script_name(english:"Jenkins Enterprise and Operations Center 2.303.x < 2.303.30.0.10 / 2.332.2.6 Multiple Vulnerabilities (CloudBees Security Advisory 2022-04-12)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins Enterprise or Jenkins Operations Center running on the remote web server is 2.303.x prior to
2.303.30.0.10, or 2.x prior to 2.332.2.6. It is, therefore, affected by multiple vulnerabilities, including the
following:

  - Jenkins Pipeline: Shared Groovy Libraries Plugin 564.ve62a_4eb_b_e039 and earlier, except 2.21.3, allows
    attackers able to submit pull requests (or equivalent), but not able to commit directly to the configured
    SCM, to effectively change the Pipeline behavior by changing the definition of a dynamically retrieved
    library in their pull request, even if the Pipeline is configured to not trust them. (CVE-2022-29047)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Subversion Plugin 2.15.3 and earlier allows
    attackers to connect to an attacker-specified URL. (CVE-2022-29048)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Publish Over FTP Plugin 1.16 and earlier
    allows attackers to connect to an FTP server using attacker-specified credentials. (CVE-2022-29050)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.cloudbees.com/security-advisories/cloudbees-security-advisory-2022-04-12
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53b982f8");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins Enterprise or Jenkins Operations Center to version 2.303.30.0.10, 2.332.2.6, or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29050");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/16");

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
  { 'min_version' : '2.303',  'fixed_version' : '2.303.30.0.10', 'edition' : make_list('Enterprise', 'Operations Center') },
  { 'min_version' : '2',      'fixed_version' : '2.332.2.6',    'edition' : make_list('Enterprise', 'Operations Center'), 'rolling_train' : TRUE },
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE, 'xsrf':TRUE}
);
