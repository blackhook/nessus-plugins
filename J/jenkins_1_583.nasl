#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78859);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2013-2186",
    "CVE-2014-1869",
    "CVE-2014-3661",
    "CVE-2014-3662",
    "CVE-2014-3663",
    "CVE-2014-3664",
    "CVE-2014-3666",
    "CVE-2014-3667",
    "CVE-2014-3678",
    "CVE-2014-3679",
    "CVE-2014-3680",
    "CVE-2014-3681"
  );
  script_bugtraq_id(63174, 65484);

  script_name(english:"Jenkins < 1.583 / 1.565.3 and Jenkins Enterprise 1.532.x / 1.554.x / 1.565.x < 1.532.10.1 / 1.554.10.1 / 1.565.3.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a job scheduling and management system
that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts a version of Jenkins (open source) or
CloudBees Jenkins Enterprise that is affected by multiple
vulnerabilities :

  - An error exists related to file upload processing that
    allows a remote attacker to overwrite arbitrary files.
    (CVE-2013-2186)

  - An input validation error exists related to the included
    'ZeroClipboard' component that allows cross-site
    scripting attacks. (CVE-2014-1869)

  - An error exists related to 'CLI handshake' handling that
    allows denial of service attacks. (CVE-2014-3661)

  - An error exists related to handling login attempts using
    non-existent or incorrect account names that allows a
    remote attacker to enumerate application user names.
    (CVE-2014-3662)

  - An error exists related to handling users having
    'Job/CONFIGURE' permissions that allows such users to
    perform actions meant only for 'Job/CREATE' permissions.
    (CVE-2014-3663)

  - An error exists related to handling users having
    'Overall/READ' permissions that allows directory
    traversal attacks. (CVE-2014-3664)

  - An error exists related to the 'CLI channel' that allows
    arbitrary code execution by a remote attacker on the
    Jenkins master. (CVE-2014-3666)

  - An error exists related to handling users having
    'Overall/READ' permissions that allows plugin source
    code to be disclosed. (CVE-2014-3667)

  - An input validation error exists related to the
    'Monitoring' plugin that allows cross-site scripting
    attacks. (CVE-2014-3678)

  - An error exists related to the 'Monitoring' plugin that
    allows unauthorized access to sensitive information.
    (CVE-2014-3679)

  - An error exists related to handling users having
    'Job/READ' permissions that allows such users to
    obtain default passwords belonging to parameterized
    jobs. (CVE-2014-3680)

  - An unspecified input validation error allows cross-site
    scripting attacks. (CVE-2014-3681)");
  # https://wiki.jenkins-ci.org/display/SECURITY/Jenkins+Security+Advisory+2014-10-01
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1236c16f");
  # https://www.cloudbees.com/jenkins-security-advisory-2014-10-01
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f0783e9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Jenkins 1.583 / 1.565.3 or Jenkins Enterprise 1.532.10.1 /
1.554.10.1 / 1.565.3.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2186");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins-ci:monitoring_plugin");
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
  { 'fixed_version' : '1.583',      'fixed_display' : '1.583 / 1.565.3',  'edition':'Open Source' },
  { 'fixed_version' : '1.565.3',    'fixed_display' : '1.583 / 1.565.3',  'edition':'Open Source LTS' },
  { 'min_version' : '1.532.1.1', 'fixed_version' : '1.532.10.1',  'fixed_display' : '1.532.10.1 / 1.554.10.1 / 1.565.3.1', 'edition':'Enterprise' },
  { 'min_version' : '1.554.1.1', 'fixed_version' : '1.554.10.1',  'fixed_display' : '1.532.10.1 / 1.554.10.1 / 1.565.3.1', 'edition':'Enterprise' },
  { 'min_version' : '1.565.1.1', 'fixed_version' : '1.565.3.1',   'fixed_display' : '1.532.10.1 / 1.554.10.1 / 1.565.3.1', 'edition':'Enterprise' },
  { 'fixed_version' : '1.554.10.1', 'edition':'Operations Center' }
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{xss:TRUE}
);
