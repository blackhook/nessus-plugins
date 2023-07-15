#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(66898);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2013-1808", "CVE-2013-2033", "CVE-2013-2034");
  script_bugtraq_id(58257, 59631, 59634);

  script_name(english:"Jenkins < 1.514 / 1.509.1 and Jenkins Enterprise 1.466.x / 1.480.x < 1.466.14.1 / 1.480.4.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a job scheduling / management system that
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts a version of Jenkins or Jenkins Enterprise
that is affected by multiple vulnerabilities :

  - The included component 'ZeroClipboard' contains an
    error in the file 'ZeroClipboard10.swf' that could
    allow cross-site scripting attacks.
    (CVE-2013-1808)

  - An unspecified cross-site scripting error exists.
    (CVE-2013-2033)

  - Multiple errors exist that could lead to cross-site
    request forgery attacks, thus allowing an attacker to
    trick an administrator into executing arbitrary code.
    (CVE-2013-2034)");
  # https://wiki.jenkins-ci.org/display/SECURITY/Jenkins+Security+Advisory+2013-05-02
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?832b8cbc");
  # https://www.cloudbees.com/jenkins-security-advisory-2013-05-02
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?13462b17");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Jenkins 1.514 / 1.509.1, Jenkins Enterprise 1.466.14.1 /
1.480.4.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2034");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Jenkins');

var constraints = [
  { 'fixed_version' : '1.514',      'fixed_display' : '1.514 / 1.509.1',  'edition':'Open Source' },
  { 'fixed_version' : '1.509.1',    'fixed_display' : '1.514 / 1.509.1',  'edition':'Open Source LTS' },
  { 'min_version' : '1.466', 'fixed_version' : '1.466.14.1',  'fixed_display' : '1.466.14.1 / 1.480.4.1', 'edition':'Enterprise' },
  { 'min_version' : '1.480', 'fixed_version' : '1.480.4.1',   'fixed_display' : '1.466.14.1 / 1.480.4.1', 'edition':'Enterprise' }
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xsrf:TRUE, xss:TRUE}
);
