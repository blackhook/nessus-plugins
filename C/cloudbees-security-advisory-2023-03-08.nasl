#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172368);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/16");

  script_cve_id(
    "CVE-2023-24998",
    "CVE-2023-27898",
    "CVE-2023-27899",
    "CVE-2023-27900",
    "CVE-2023-27901",
    "CVE-2023-27902",
    "CVE-2023-27903",
    "CVE-2023-27904"
  );
  script_xref(name:"IAVA", value:"2023-A-0127-S");

  script_name(english:"Jenkins Enterprise and Operations Center 2.346.x < 2.346.40.0.8 Multiple Vulnerabilities (CloudBees Security Advisory 2023-03-08)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins Enterprise or Jenkins Operations Center running on the remote web server is 2.346.x prior to
2.346.40.0.8. It is, therefore, affected by multiple vulnerabilities including the following:

  - DoS vulnerability in bundled Apache Commons FileUpload library (CVE-2023-24998, CVE-2023-27900,
    CVE-2023-27901)

  - XSS vulnerability in plugin manager (CVE-2023-27898)

  - Temporary plugin file created with insecure permissions (CVE-2023-27899)

  - Workspace temporary directories accessible through directory browser (CVE-2023-27902)

  - Temporary file parameter created with insecure permissions (CVE-2023-27903)

  - Information disclosure through error stack traces related to agents (CVE-2023-27904)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.cloudbees.com/security-advisories/cloudbees-security-advisory-2023-03-08
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c6481b1");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins Enterprise or Jenkins Operations Center to version 2.346.40.0.8 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-27899");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Jenkins');

var constraints = [
  {
    'min_version' : '2.346',
    'fixed_version' :'2.346.40.0.8',
    'edition' : make_list('Enterprise', 'Operations Center')
  }
];

vcf::jenkins::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
