#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155633);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2021-21623",
    "CVE-2021-21624",
    "CVE-2021-21625",
    "CVE-2021-21626",
    "CVE-2021-21627"
  );

  script_name(english:"Jenkins Enterprise and Operations Center < 2.222.43.0.3 rev2 / 2.249.30.0.3 rev2 / 2.277.1.2 rev2 Multiple Vulnerabilities (CloudBees Security Advisory 2021-03-18)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins Enterprise or Jenkins Operations Center running on the remote web server is 2.222.x prior to
2.222.43.0.3 rev2, 2.249.x prior to 2.249.30.0.3 rev2, or 2.x prior to 2.277.1.2 rev2. It is, therefore, affected by
multiple vulnerabilities, including the following:

  - An incorrect permission check in Jenkins Matrix Authorization Strategy Plugin 2.6.5 and earlier allows
    attackers with Item/Read permission on nested items to access them, even if they lack Item/Read permission
    for parent folders. (CVE-2021-21623)

  - An incorrect permission check in Jenkins Role-based Authorization Strategy Plugin 3.1 and earlier allows
    attackers with Item/Read permission on nested items to access them, even if they lack Item/Read permission
    for parent folders. (CVE-2021-21624)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Libvirt Agents Plugin 1.9.0 and earlier
    allows attackers to stop hypervisor domains. (CVE-2021-21627)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cloudbees.com/cloudbees-security-advisory-2021-03-18");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins Enterprise or Jenkins Operations Center to version 2.222.43.0.3 rev2, 2.249.30.0.3 rev2, 2.277.1.2 rev2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21627");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/19");

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

# Cannot determine if the version is "rev2"
if ((app_info.version == '2.222.43.0.3' || app_info.version == '2.249.30.0.3' || app_info.version == '2.277.1.2') && app_info.Edition =~ '(Enterprise|Operations Center)' && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, app_info['version'], app_info['app']);

var constraints = [
  { 'min_version' : '2.222',  'fixed_version' : '2.222.43.0.4', 'fixed_display' : '2.222.43.0.3 rev2',  'edition' : make_list('Enterprise', 'Operations Center') },
  { 'min_version' : '2.249',  'fixed_version' : '2.249.30.0.4', 'fixed_display' : '2.249.30.0.3 rev2',  'edition' : make_list('Enterprise', 'Operations Center') },
  { 'min_version' : '2',      'fixed_version' : '2.277.1.3',    'fixed_display' : '2.277.1.2 rev2',     'edition' : make_list('Enterprise', 'Operations Center'), 'rolling_train' : TRUE },
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xsrf':TRUE}
);
