#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165693);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/06");

  script_cve_id(
    "CVE-2021-25738",
    "CVE-2022-38663",
    "CVE-2022-38664",
    "CVE-2022-38665"
  );

  script_name(english:"Jenkins Enterprise and Operations Center 2.303.x < 2.303.30.0.16 / 2.346.4.1 Multiple Vulnerabilities (CloudBees Security Advisory 2022-08-27)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins Enterprise or Jenkins Operations Center running on the remote web server is 2.303.x prior to
2.303.30.0.16, or 2.x prior to 2.346.4.1. It is, therefore, affected by multiple vulnerabilities, including
the following:

  - Loading specially-crafted yaml with the Kubernetes Java Client library can lead to code execution.
    (CVE-2021-25738)

  - Jenkins Git Plugin 4.11.4 and earlier does not properly mask (i.e., replace with asterisks) credentials in
    the build log provided by the Git Username and Password (`gitUsernamePassword`) credentials binding.
    (CVE-2022-38663)

  - Jenkins CollabNet Plugins Plugin 2.0.8 and earlier stores a RabbitMQ password unencrypted in its global
    configuration file on the Jenkins controller where it can be viewed by users with access to the Jenkins
    controller file system. (CVE-2022-38665)
  
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.cloudbees.com/security-advisories/cloudbees-security-advisory-2022-08-23
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db9feca3");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins Enterprise or Jenkins Operations Center to version 2.303.30.0.16, 2.346.4.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25738");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/05");

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
  { 'min_version' : '2.303', 'fixed_version' : '2.303.30.0.16', 'edition' : make_list('Enterprise', 'Operations Center') },
  { 'min_version' : '2',     'fixed_version' : '2.346.4.1',     'edition' : make_list('Enterprise', 'Operations Center'), 'rolling_train' : TRUE },
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
