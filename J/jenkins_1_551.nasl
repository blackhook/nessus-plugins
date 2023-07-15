#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72685);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2013-5573",
    "CVE-2013-7285",
    "CVE-2013-7330",
    "CVE-2014-2058",
    "CVE-2014-2060",
    "CVE-2014-2061",
    "CVE-2014-2062",
    "CVE-2014-2063",
    "CVE-2014-2064",
    "CVE-2014-2065",
    "CVE-2014-2066",
    "CVE-2014-2068"
  );
  script_bugtraq_id(
    64414,
    64760,
    65694,
    65718,
    65720
  );

  script_name(english:"Jenkins < 1.551 / 1.532.2 and Jenkins Enterprise 1.509.x / 1.532.x < 1.509.5.1 / 1.532.2.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a job scheduling / management system that
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts a version of Jenkins or Jenkins Enterprise
that is affected by multiple vulnerabilities :

  - A flaw in the default markup formatter allows cross-site
    scripting via the Description field in the user
    configuration. (CVE-2013-5573)

  - A security bypass vulnerability allows remote
    authenticated attackers to change configurations and
    execute arbitrary jobs. (CVE-2013-7285, CVE-2013-7330,
    CVE-2014-2058)

  - An unspecified flaw in the Winstone servlet allows
    remote attackers to hijack sessions. (CVE-2014-2060)

  - An input control flaw in 'PasswordParameterDefinition'
    allows remote attackers to disclose sensitive
    information including passwords. (CVE-2014-2061)

  - A security bypass vulnerability due to API tokens not
    being invalidated when a user is deleted.
    (CVE-2014-2062)

  - An unspecified flaw allows remote attackers to conduct
    clickjacking attacks. (CVE-2014-2063)

  - An information disclosure vulnerability in the
    'loadUserByUsername' function allows remote attackers
    to determine whether a user exists via vectors related
    to failed login attempts. (CVE-2014-2064)

  - A cross-site scripting vulnerability due to improper
    input validation to the 'iconSize' cookie.
    (CVE-2014-2065)

  - A session fixation vulnerability allows remote attackers
    to hijack web sessions. (CVE-2014-2066)

  - An information disclosure vulnerability in the 'doIndex'
    function in 'hudson/util/RemotingDiagnostics.java'
    allows remote authenticated users with the
    'ADMINISTRATOR' permission to obtain sensitive
    information via heapDump. (CVE-2014-2068)");
  # https://wiki.jenkins.io/display/SECURITY/Jenkins%20Security%20Advisory%202014-02-14
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0db81363");
  # https://www.cloudbees.com/jenkins-security-advisory-2014-02-14
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?353dd087");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Jenkins 1.551 / 1.532.2 or Jenkins Enterprise 1.509.5.1 /
1.532.2.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-2063");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Jenkins');

var constraints = [
  { 'fixed_version' : '1.551',      'fixed_display' : '1.551 / 1.532.2',  'edition':'Open Source' },
  { 'fixed_version' : '1.532.2',    'fixed_display' : '1.551 / 1.532.2',  'edition':'Open Source LTS' },
  { 'min_version' : '1.509', 'fixed_version' : '1.509.5.1',  'fixed_display' : '1.509.5.1 / 1.532.2.2', 'edition':'Enterprise' },
  { 'min_version' : '1.532', 'fixed_version' : '1.532.2.2',  'fixed_display' : '1.509.5.1 / 1.532.2.2', 'edition':'Enterprise' }
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{xss:TRUE}
);
