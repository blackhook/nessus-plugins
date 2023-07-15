#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99984);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2017-1000353",
    "CVE-2017-1000354",
    "CVE-2017-1000355",
    "CVE-2017-1000356"
  );
  script_bugtraq_id(
    98056,
    98062,
    98065,
    98066
  );

  script_name(english:"Jenkins < 2.46.2 / 2.57 and Jenkins Enterprise < 1.625.24.1 / 1.651.24.1 / 2.7.24.0.1 / 2.46.2.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins running on the remote web server is prior to
2.57 or is a version of Jenkins LTS prior to 2.46.2, or else it is
a version of Jenkins Enterprise that is 1.625.x.y prior to 1.625.24.1,
1.651.x.y prior to 1.651.24.1, 2.7.x.0.y prior to 2.7.24.0.1, or
2.x.y.z prior to 2.46.2.1. It is, therefore, affected by multiple
vulnerabilities :

  - A remote code execution vulnerability exists within
    core/src/main/java/jenkins/model/Jenkins.java that
    allows an untrusted serialized Java SignedObject to be
    transfered to the remoting-based Jenkins CLI and
    deserialized using a new ObjectInputStream. By using a
    specially crafted request, an unauthenticated, remote
    attacker can exploit this issue to bypass existing
    blacklist protection mechanisms and execute arbitrary
    code. (CVE-2017-1000353)

  - A flaw exists in the remoting-based CLI, specifically in
    the ClientAuthenticationCache.java class, when storing
    the encrypted username of a successfully authenticated
    user in a cache file that is used to authenticate
    further commands. An authenticated, remote attacker who
    has sufficient permissions to create secrets in Jenkins
    and download their encrypted values can exploit this
    issue to impersonate any other Jenkins user on the same
    instance. (CVE-2017-1000354)

  - A denial of service vulnerability exists in the XStream
    library. An authenticated, remote attacker who has
    sufficient permissions, such as creating or configuring
    items, views or jobs, can exploit this to crash the Java
    process by using specially crafted XML content.
    (CVE-2017-1000355)

  - Cross-site request forgery (XSRF) vulnerabilities exist
    within multiple Java classes due to a failure to require
    multiple steps, explicit confirmation, or a unique token
    when performing certain sensitive actions. An
    unauthenticated, remote attacker can exploit these to
    perform several administrative actions by convincing a
    user into opening a specially crafted web page.
    (CVE-2017-1000356)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cloudbees.com/cloudbees-security-advisory-2017-04-26");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2017-04-26/");
  # https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c6d83db");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins to version 2.57 or later, Jenkins LTS to version
2.46.2 or later, or Jenkins Enterprise to version 1.625.24.1 /
1.651.24.1 / 2.7.24.0.1 / 2.46.2.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1000353");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Jenkins');

var constraints = [
  { 'fixed_version' : '2.57',    'edition':'Open Source' },
  { 'fixed_version' : '2.46.2',  'edition':'Open Source LTS' },
  { 'min_version' : '1.651',  'fixed_version' : '1.651.24.1', 'edition':'Enterprise' },
  { 'min_version' : '2.7',    'fixed_version' : '2.7.24.0.1', 'edition':'Enterprise' },
  { 'min_version' : '2',      'fixed_version' : '2.46.2.1',   'edition':'Enterprise', 'rolling_train' : TRUE },
  { 'min_version' : '1.625',  'fixed_version' : '1.625.24.1', 'edition':'Operations Center' },
  { 'min_version' : '2.7',    'fixed_version' : '2.7.24.0.1', 'edition':'Operations Center' },
  { 'min_version' : '2',      'fixed_version' : '2.46.2.1',   'edition':'Operations Center', 'rolling_train' : TRUE }
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{xsrf:TRUE}
);
