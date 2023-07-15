#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130099);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id(
    "CVE-2019-10401",
    "CVE-2019-10402",
    "CVE-2019-10403",
    "CVE-2019-10404",
    "CVE-2019-10405",
    "CVE-2019-10406"
  );

  script_name(english:"Jenkins < 2.176.4 LTS / 2.197 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins running on the remote web server is prior to 2.197 or is a version of Jenkins LTS prior to
2.176.4. It is, therefore, affected by multiple vulnerabilities:

  - An information disclosure vulnerability exists in the /whoAmI/ URL due to the exposed 'Cookie' HTTP
    Header. An authenticated, remote attacker can exploit this, via a separate Cross-site scripting (XSS)
    vulnerability, to disclose potentially sensitive information. (CVE-2019-10405)

  - A stored Cross-site scripting (XSS) vulnerability exists in the f:formbox form control due to the form
    control interpreting its item labels as HTML. An authenticated, remote attacker with permission to control
    the contents of f:formbox form controls can exploit this to execute arbitrary script code in a user's
    browser session. (CVE-2019-10402)

  - A stored Cross-site scripting (XSS) vulnerability exists in the tooltip for SCM tag actions due to the
    application not escaping characters in the SCM tag name. An authenticated, remote attacker with
    permission to control SCM tag names can exploit this to execute arbitrary code in a user's browser
    session.  (CVE-2019-10403)

The version of Jenkins running on the remote web server is also affected by other Cross-site scripting (XSS)
vulnerabilities. (CVE-2019-10401, CVE-2019-10404, CVE-2019-10406)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2019-09-25/");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins to version 2.197 or later, Jenkins LTS to version 2.176.4 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10406");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-10405");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Jenkins');

var constraints = [
  { 'fixed_version' : '2.197',    'fixed_display' : '2.176.4 LTS / 2.197',  'edition' : 'Open Source' },
  { 'fixed_version' : '2.176.4',  'fixed_display' : '2.176.4 LTS / 2.197',  'edition' : 'Open Source LTS' }
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE,
  flags:{xss:true}
);
