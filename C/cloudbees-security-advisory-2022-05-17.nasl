##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161453);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/17");

  script_cve_id(
    "CVE-2022-30945",
    "CVE-2022-30946",
    "CVE-2022-30947",
    "CVE-2022-30948",
    "CVE-2022-30949",
    "CVE-2022-30950",
    "CVE-2022-30951",
    "CVE-2022-30952",
    "CVE-2022-30953",
    "CVE-2022-30954",
    "CVE-2022-30955",
    "CVE-2022-30956",
    "CVE-2022-30957",
    "CVE-2022-30958",
    "CVE-2022-30959",
    "CVE-2022-30960",
    "CVE-2022-30961",
    "CVE-2022-30962",
    "CVE-2022-30963",
    "CVE-2022-30964",
    "CVE-2022-30965",
    "CVE-2022-30966",
    "CVE-2022-30967",
    "CVE-2022-30968",
    "CVE-2022-30969",
    "CVE-2022-30970",
    "CVE-2022-30971",
    "CVE-2022-30972"
  );

  script_name(english:"Jenkins Enterprise and Operations Center 2.303.x < 2.303.30.0.13 / 2.332.3.4 Multiple Vulnerabilities (CloudBees Security Advisory 2022-05-17)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins Enterprise or Jenkins Operations Center running on the remote web server is 2.303.x prior to
2.303.30.0.13, or 2.x prior to 2.332.3.4. It is, therefore, affected by multiple vulnerabilities, including the
following:

  - Jenkins Rundeck Plugin 3.6.10 and earlier does not restrict URL schemes in Rundeck webhook submissions,
    resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers able to submit
    crafted Rundeck webhook payloads. (CVE-2022-30956)

  - Jenkins Application Detector Plugin 1.0.8 and earlier does not escape the name of Chois Application
    Version parameters on views displaying parameters, resulting in a stored cross-site scripting (XSS)
    vulnerability exploitable by attackers with Item/Configure permission. (CVE-2022-30960)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Autocomplete Parameter Plugin 1.1 and earlier
    allows attackers to execute arbitrary code without sandbox protection if the victim is an administrator.
    (CVE-2022-30969)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.cloudbees.com/security-advisories/cloudbees-security-advisory-2022-04-12
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53b982f8");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins Enterprise or Jenkins Operations Center to version 2.303.30.0.13, 2.332.3.4, or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30972");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/24");

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
  { 'min_version' : '2.303',  'fixed_version' : '2.303.30.0.13', 'edition' : make_list('Enterprise', 'Operations Center') },
  { 'min_version' : '2',      'fixed_version' : '2.332.3.4',    'edition' : make_list('Enterprise', 'Operations Center'), 'rolling_train' : TRUE },
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE, 'xsrf':TRUE}
);
