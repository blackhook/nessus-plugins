#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158977);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_cve_id(
    "CVE-2022-27195",
    "CVE-2022-27196",
    "CVE-2022-27197",
    "CVE-2022-27198",
    "CVE-2022-27199",
    "CVE-2022-27200",
    "CVE-2022-27201",
    "CVE-2022-27202",
    "CVE-2022-27203",
    "CVE-2022-27204",
    "CVE-2022-27205",
    "CVE-2022-27206",
    "CVE-2022-27207",
    "CVE-2022-27208",
    "CVE-2022-27209",
    "CVE-2022-27210",
    "CVE-2022-27211",
    "CVE-2022-27212",
    "CVE-2022-27213",
    "CVE-2022-27214",
    "CVE-2022-27215",
    "CVE-2022-27216",
    "CVE-2022-27217",
    "CVE-2022-27218"
  );

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2022-03-15)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its their self-reported version number, the version of Jenkins plugins running on the remote web server are
Jenkins CloudBees AWS Credentials Plugin prior to 191., Dashboard View Plugin prior to 2.18.1, Environment Dashboard
Plugin 1.1.10 or earlier, Extended Choice Parameter Plugin 346. or earlier, Favorite Plugin prior to 2.4.1, Folder-based
Authorization Strategy Plugin prior to 1.4, GitLab Authentication Plugin 1.13 or earlier, Kubernetes Continuous Deploy
Plugin 2.3.1 or earlier, List Git Branches Parameter Plugin 0.0.9 or earlier, Parameterized Trigger Plugin prior to
2.43.1, Release Helper Plugin 1.3.3 or earlier, Semantic Versioning Plugin prior to 1.14, Vmware vRealize CodeStream
Plugin 1.2 or earlier, dbCharts Plugin 0.5.2 or earlier, global-build-stats Plugin 1.5 or earlier, incapptic connect
uploader Plugin 1.15 or earlier. They are, therefore, affected by multiple vulnerabilities:

  - Jenkins Parameterized Trigger Plugin 2.43 and earlier captures environment variables passed to builds
    triggered using Jenkins Parameterized Trigger Plugin, including password parameter values, in their
    `build.xml` files. These values are stored unencrypted and can be viewed by users with access to the
    Jenkins controller file system. (CVE-2022-27195)

  - Jenkins Favorite Plugin 2.4.0 and earlier does not escape the names of jobs in the favorite column,
    resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers with
    Item/Configure or Item/Create permissions. (CVE-2022-27196)

  - Jenkins Dashboard View Plugin 2.18 and earlier does not perform URL validation for the Iframe Portlet's
    Iframe source URL, resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers
    able to configure views. (CVE-2022-27197)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins CloudBees AWS Credentials Plugin
    189.v3551d5642995 and earlier allows attackers with Overall/Read permission to connect to an AWS service
    using an attacker-specified token. (CVE-2022-27198)

  - A missing permission check in Jenkins CloudBees AWS Credentials Plugin 189.v3551d5642995 and earlier
    allows attackers with Overall/Read permission to connect to an AWS service using an attacker-specified
    token. (CVE-2022-27199)

  - Jenkins Folder-based Authorization Strategy Plugin 1.3 and earlier does not escape the names of roles
    shown on the configuration form, resulting in a stored cross-site scripting (XSS) vulnerability
    exploitable by attackers with Overall/Administer permission. (CVE-2022-27200)

  - Jenkins Semantic Versioning Plugin 1.13 and earlier does not restrict execution of an controller/agent
    message to agents, and implements no limitations about the file path that can be parsed, allowing
    attackers able to control agent processes to have Jenkins parse a crafted file that uses external entities
    for extraction of secrets from the Jenkins controller or server-side request forgery. (CVE-2022-27201)

  - Jenkins Extended Choice Parameter Plugin 346.vd87693c5a_86c and earlier does not escape the value and
    description of extended choice parameters of radio buttons or check boxes type, resulting in a stored
    cross-site scripting (XSS) vulnerability exploitable by attackers with Item/Configure permission.
    (CVE-2022-27202)

  - Jenkins Extended Choice Parameter Plugin 346.vd87693c5a_86c and earlier allows attackers with
    Item/Configure permission to read values from arbitrary JSON and Java properties files on the Jenkins
    controller. (CVE-2022-27203)

  - A cross-site request forgery vulnerability in Jenkins Extended Choice Parameter Plugin 346.vd87693c5a_86c
    and earlier allows attackers to connect to an attacker-specified URL. (CVE-2022-27204)

  - A missing permission check in Jenkins Extended Choice Parameter Plugin 346.vd87693c5a_86c and earlier
    allows attackers with Overall/Read permission to connect to an attacker-specified URL. (CVE-2022-27205)

  - Jenkins GitLab Authentication Plugin 1.13 and earlier stores the GitLab client secret unencrypted in the
    global config.xml file on the Jenkins controller where it can be viewed by users with access to the
    Jenkins controller file system. (CVE-2022-27206)

  - Jenkins global-build-stats Plugin 1.5 and earlier does not escape multiple fields in the chart
    configuration on the 'Global Build Stats' page, resulting in a stored cross-site scripting (XSS)
    vulnerability exploitable by attackers with Overall/Administer permission. (CVE-2022-27207)

  - Jenkins Kubernetes Continuous Deploy Plugin 2.3.1 and earlier allows users with Credentials/Create
    permission to read arbitrary files on the Jenkins controller. (CVE-2022-27208)

  - A missing permission check in Jenkins Kubernetes Continuous Deploy Plugin 2.3.1 and earlier allows
    attackers with Overall/Read permission to enumerate credentials IDs of credentials stored in Jenkins.
    (CVE-2022-27209)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Kubernetes Continuous Deploy Plugin 2.3.1 and
    earlier allows attackers to connect to an attacker-specified SSH server using attacker-specified
    credentials IDs obtained through another method, capturing credentials stored in Jenkins. (CVE-2022-27210)

  - A missing/An incorrect permission check in Jenkins Kubernetes Continuous Deploy Plugin 2.3.1 and earlier
    allows attackers with Overall/Read permission to connect to an attacker-specified SSH server using
    attacker-specified credentials IDs obtained through another method, capturing credentials stored in
    Jenkins. (CVE-2022-27211)

  - Jenkins List Git Branches Parameter Plugin 0.0.9 and earlier does not escape the name of the 'List Git
    branches (and more)' parameter, resulting in a stored cross-site scripting (XSS) vulnerability exploitable
    by attackers with Item/Configure permission. (CVE-2022-27212)

  - Jenkins Environment Dashboard Plugin 1.1.10 and earlier does not escape the Environment order and the
    Component order configuration values in its views, resulting in a stored cross-site scripting (XSS)
    vulnerability exploitable by attackers with View/Configure permission. (CVE-2022-27213)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Release Helper Plugin 1.3.3 and earlier
    allows attackers to connect to an attacker-specified URL using attacker-specified credentials.
    (CVE-2022-27214)

  - A missing permission check in Jenkins Release Helper Plugin 1.3.3 and earlier allows attackers with
    Overall/Read permission to connect to an attacker-specified URL using attacker-specified credentials.
    (CVE-2022-27215)

  - Jenkins dbCharts Plugin 0.5.2 and earlier stores JDBC connection passwords unencrypted in its global
    configuration file on the Jenkins controller where they can be viewed by users with access to the Jenkins
    controller file system. (CVE-2022-27216)

  - Jenkins Vmware vRealize CodeStream Plugin 1.2 and earlier stores passwords unencrypted in job config.xml
    files on the Jenkins controller where they can be viewed by users with Extended Read permission, or access
    to the Jenkins controller file system. (CVE-2022-27217)

  - Jenkins incapptic connect uploader Plugin 1.15 and earlier stores tokens unencrypted in job config.xml
    files on the Jenkins controller where they can be viewed by users with Extended Read permission, or access
    to the Jenkins controller file system. (CVE-2022-27218)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2022-03-15");
  script_set_attribute(attribute:"solution", value:
"Upgrade Semantic Versioning Plugin to version 1.14 or later, Parameterized Trigger Plugin to version 2.43.1 or later,
Folder-based Authorization Strategy Plugin to version 1.4 or later, Favorite Plugin to version 2.4.1 or later, Dashboard
View Plugin to version 2.18.1 or later, CloudBees AWS Credentials Plugin to version 191. or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27204");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_plugins_detect.nbin", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var constraints = [
  { 'max_version' : '1.15', 'plugin' : 'incapptic connect uploader plugin', 'fixed_display' : 'See vendor advisory' },
  { 'max_version' : '1.5', 'plugin' : 'Hudson global-build-stats plugin', 'fixed_display' : 'See vendor advisory' },
  { 'max_version' : '0.5.2', 'plugin' : 'dbCharts', 'fixed_display' : 'See vendor advisory' },
  { 'max_version' : '1.2', 'plugin' : 'Vmware vRealize CodeStream Plugin', 'fixed_display' : 'See vendor advisory' },
  { 'max_version' : '1.13', 'fixed_version' : '1.14', 'plugin' : 'Semantic Versioning Plugin' },
  { 'max_version' : '1.3.3', 'plugin' : 'Jenkins Release Helper Plugin', 'fixed_display' : 'See vendor advisory' },
  { 'max_version' : '2.43', 'fixed_version' : '2.43.1', 'plugin' : 'Jenkins Parameterized Trigger plugin' },
  { 'max_version' : '0.0.9', 'plugin' : 'List Git Branches Parameter PlugIn', 'fixed_display' : 'See vendor advisory' },
  { 'max_version' : '2.3.1', 'plugin' : 'Kubernetes Continuous Deploy Plugin', 'fixed_display' : 'See vendor advisory' },
  { 'max_version' : '1.13', 'plugin' : 'GitLab Authentication plugin', 'fixed_display' : 'See vendor advisory' },
  { 'max_version' : '1.3', 'fixed_version' : '1.4', 'plugin' : 'Folder-based Authorization Strategy' },
  { 'max_version' : '2.4.0', 'fixed_version' : '2.4.1', 'plugin' : 'Favorite' },
  { 'max_version' : '346.', 'plugin' : 'Extended Choice Parameter Plug-In', 'fixed_display' : 'See vendor advisory' },
  { 'max_version' : '1.1.10', 'plugin' : 'Environment Dashboard Plugin', 'fixed_display' : 'See vendor advisory' },
  { 'max_version' : '2.18', 'fixed_version' : '2.18.1', 'plugin' : 'Dashboard View' },
  { 'max_version' : '189.', 'fixed_version' : '191.', 'plugin' : 'CloudBees AWS Credentials Plugin' }
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

var flags = {'xsrf':TRUE, 'xss':TRUE};
vcf::jenkins::plugin::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:flags);
