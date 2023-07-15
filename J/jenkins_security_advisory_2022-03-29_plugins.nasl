#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159377);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_cve_id(
    "CVE-2022-28133",
    "CVE-2022-28134",
    "CVE-2022-28135",
    "CVE-2022-28136",
    "CVE-2022-28137",
    "CVE-2022-28138",
    "CVE-2022-28139",
    "CVE-2022-28140",
    "CVE-2022-28141",
    "CVE-2022-28142",
    "CVE-2022-28143",
    "CVE-2022-28144",
    "CVE-2022-28145",
    "CVE-2022-28146",
    "CVE-2022-28147",
    "CVE-2022-28148",
    "CVE-2022-28149",
    "CVE-2022-28150",
    "CVE-2022-28151",
    "CVE-2022-28152",
    "CVE-2022-28153",
    "CVE-2022-28154",
    "CVE-2022-28155",
    "CVE-2022-28156",
    "CVE-2022-28157",
    "CVE-2022-28158",
    "CVE-2022-28159",
    "CVE-2022-28160"
  );

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2022-03-29)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its their self-reported version number, the version of Jenkins plugins running on the remote web server are
Jenkins Bitbucket Server Integration Plugin prior to 3.2.0, Continuous Integration with Toad Edge Plugin prior to 2.4,
Coverage/Complexity Scatter Plot Plugin 1.1.1 or earlier, Flaky Test Handler Plugin prior to 1.2.2,
JiraTestResultReporter Plugin prior to 166., Job and Node ownership Plugin 0.13.0 or earlier, Pipeline: Phoenix AutoTest
Plugin 1.3 or earlier, Proxmox Plugin prior to 0.7.1, RocketChat Notifier Plugin prior to 1.5.0, SiteMonitor Plugin 0.6
or earlier, Tests Selector Plugin 1.3.3 or earlier, instant-messaging Plugin prior to 1.42. They are, therefore,
affected by multiple vulnerabilities:

  - Jenkins Bitbucket Server Integration Plugin 3.1.0 and earlier does not limit URL schemes for callback URLs
    on OAuth consumers, resulting in a stored cross-site scripting (XSS) vulnerability exploitable by
    attackers able to create BitBucket Server consumers. (CVE-2022-28133)

  - Jenkins Bitbucket Server Integration Plugin 3.1.0 and earlier does not perform permission checks in
    several HTTP endpoints, allowing attackers with Overall/Read permission to create, view, and delete
    BitBucket Server consumers. (CVE-2022-28134)

  - Jenkins instant-messaging Plugin 1.41 and earlier stores passwords for group chats unencrypted in the
    global configuration file of plugins based on Jenkins instant-messaging Plugin on the Jenkins controller
    where they can be viewed by users with access to the Jenkins controller file system. (CVE-2022-28135)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins JiraTestResultReporter Plugin
    165.v817928553942 and earlier allows attackers to connect to an attacker-specified URL using attacker-
    specified credentials. (CVE-2022-28136)

  - A missing permission check in Jenkins JiraTestResultReporter Plugin 165.v817928553942 and earlier allows
    attackers with Overall/Read permission to connect to an attacker-specified URL using attacker-specified
    credentials. (CVE-2022-28137)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins RocketChat Notifier Plugin 1.4.10 and earlier
    allows attackers to connect to an attacker-specified URL using attacker-specified credential.
    (CVE-2022-28138)

  - A missing permission check in Jenkins RocketChat Notifier Plugin 1.4.10 and earlier allows attackers with
    Overall/Read permission to connect to an attacker-specified URL using attacker-specified credentials.
    (CVE-2022-28139)

  - Jenkins Flaky Test Handler Plugin 1.2.1 and earlier does not configure its XML parser to prevent XML
    external entity (XXE) attacks. (CVE-2022-28140)

  - Jenkins Proxmox Plugin 0.5.0 and earlier stores the Proxmox Datacenter password unencrypted in the global
    config.xml file on the Jenkins controller where it can be viewed by users with access to the Jenkins
    controller file system. (CVE-2022-28141)

  - Jenkins Proxmox Plugin 0.6.0 and earlier disables SSL/TLS certificate validation globally for the Jenkins
    controller JVM when configured to ignore SSL/TLS issues. (CVE-2022-28142)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Proxmox Plugin 0.7.0 and earlier allows
    attackers to connect to an attacker-specified host using attacker-specified username and password (perform
    a connection test), disable SSL/TLS validation for the entire Jenkins controller JVM as part of the
    connection test (see CVE-2022-28142), and test a rollback with attacker-specified parameters.
    (CVE-2022-28143)

  - Jenkins Proxmox Plugin 0.7.0 and earlier does not perform a permission check in several HTTP endpoints,
    allowing attackers with Overall/Read permission to connect to an attacker-specified host using attacker-
    specified username and password (perform a connection test), disable SSL/TLS validation for the entire
    Jenkins controller JVM as part of the connection test (see CVE-2022-28142), and test a rollback with
    attacker-specified parameters. (CVE-2022-28144)

  - Jenkins Continuous Integration with Toad Edge Plugin 2.3 and earlier does not apply Content-Security-
    Policy headers to report files it serves, resulting in a stored cross-site scripting (XSS) exploitable by
    attackers with Item/Configure permission or otherwise able to control report contents. (CVE-2022-28145)

  - Jenkins Continuous Integration with Toad Edge Plugin 2.3 and earlier allows attackers with Item/Configure
    permission to read arbitrary files on the Jenkins controller by specifying an input folder on the Jenkins
    controller as a parameter to its build steps. (CVE-2022-28146)

  - A missing permission check in Jenkins Continuous Integration with Toad Edge Plugin 2.3 and earlier allows
    attackers with Overall/Read permission to check for the existence of an attacker-specified file path on
    the Jenkins controller file system. (CVE-2022-28147)

  - The file browser in Jenkins Continuous Integration with Toad Edge Plugin 2.3 and earlier may interpret
    some paths to files as absolute on Windows, resulting in a path traversal vulnerability allowing attackers
    with Item/Read permission to obtain the contents of arbitrary files on Windows controllers.
    (CVE-2022-28148)

  - Jenkins Job and Node ownership Plugin 0.13.0 and earlier does not escape the names of the secondary
    owners, resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers with
    Item/Configure permission. (CVE-2022-28149)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Job and Node ownership Plugin 0.13.0 and
    earlier allows attackers to change the owners and item-specific permissions of a job. (CVE-2022-28150)

  - A missing permission check in Jenkins Job and Node ownership Plugin 0.13.0 and earlier allows attackers
    with Item/Read permission to change the owners and item-specific permissions of a job. (CVE-2022-28151)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Job and Node ownership Plugin 0.13.0 and
    earlier allows attackers to restore the default ownership of a job. (CVE-2022-28152)

  - Jenkins SiteMonitor Plugin 0.6 and earlier does not escape URLs of sites to monitor in tooltips, resulting
    in a stored cross-site scripting (XSS) vulnerability exploitable by attackers with Item/Configure
    permission. (CVE-2022-28153)

  - Jenkins Coverage/Complexity Scatter Plot Plugin 1.1.1 and earlier does not configure its XML parser to
    prevent XML external entity (XXE) attacks. (CVE-2022-28154)

  - Jenkins Pipeline: Phoenix AutoTest Plugin 1.3 and earlier does not configure its XML parser to prevent XML
    external entity (XXE) attacks. (CVE-2022-28155)

  - Jenkins Pipeline: Phoenix AutoTest Plugin 1.3 and earlier allows attackers with Item/Configure permission
    to copy arbitrary files and directories from the Jenkins controller to the agent workspace.
    (CVE-2022-28156)

  - Jenkins Pipeline: Phoenix AutoTest Plugin 1.3 and earlier allows attackers with Item/Configure permission
    to upload arbitrary files from the Jenkins controller via FTP to an attacker-specified FTP server.
    (CVE-2022-28157)

  - A missing permission check in Jenkins Pipeline: Phoenix AutoTest Plugin 1.3 and earlier allows attackers
    with Overall/Read permission to enumerate credentials IDs of credentials stored in Jenkins.
    (CVE-2022-28158)

  - Jenkins Tests Selector Plugin 1.3.3 and earlier does not escape the Properties File Path option for
    Choosing Tests parameters, resulting in a stored cross-site scripting (XSS) vulnerability exploitable by
    attackers with Item/Configure permission. (CVE-2022-28159)

  - Jenkins Tests Selector Plugin 1.3.3 and earlier allows users with Item/Configure permission to read
    arbitrary files on the Jenkins controller. (CVE-2022-28160)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2022-03-29");
  script_set_attribute(attribute:"solution", value:
"Upgrade instant-messaging Plugin to version 1.42 or later, RocketChat Notifier Plugin to version 1.5.0 or later, Proxmox
Plugin to version 0.7.1 or later, JiraTestResultReporter Plugin to version 166. or later, Flaky Test Handler Plugin to
version 1.2.2 or later, Continuous Integration with Toad Edge Plugin to version 2.4 or later, Bitbucket Server
Integration Plugin to version 3.2.0 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28150");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/31");

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
include('jenkins_plugin_mappings.inc');

var constraints = [
  { 'max_version' : '1.41', 'fixed_version' : '1.42', 'plugin' : jenkins_plugin_mappings['instant-messaging Plugin'] },
  { 'max_version' : '1.3.3', 'plugin' : jenkins_plugin_mappings['Tests Selector Plugin'], 'fixed_display' : 'See vendor advisory' },
  { 'max_version' : '0.6', 'plugin' : jenkins_plugin_mappings['SiteMonitor Plugin'], 'fixed_display' : 'See vendor advisory' },
  { 'max_version' : '1.4.10', 'fixed_version' : '1.5.0', 'plugin' : jenkins_plugin_mappings['RocketChat Notifier Plugin'] },
  { 'max_version' : '0.7.0', 'fixed_version' : '0.7.1', 'plugin' : jenkins_plugin_mappings['Proxmox Plugin'] },
  { 'max_version' : '1.3', 'plugin' : jenkins_plugin_mappings['Pipeline: Phoenix AutoTest Plugin'], 'fixed_display' : 'See vendor advisory' },
  { 'max_version' : '0.13.0', 'plugin' : jenkins_plugin_mappings['Job and Node ownership Plugin'], 'fixed_display' : 'See vendor advisory' },
  { 'max_version' : '165.', 'fixed_version' : '166.', 'plugin' : jenkins_plugin_mappings['JiraTestResultReporter Plugin'] },
  { 'max_version' : '1.2.1', 'fixed_version' : '1.2.2', 'plugin' : jenkins_plugin_mappings['Flaky Test Handler Plugin'] },
  { 'max_version' : '1.1.1', 'plugin' : jenkins_plugin_mappings['Coverage/Complexity Scatter Plot Plugin'], 'fixed_display' : 'See vendor advisory' },
  { 'max_version' : '2.3', 'fixed_version' : '2.4', 'plugin' : jenkins_plugin_mappings['Continuous Integration with Toad Edge Plugin'] },
  { 'max_version' : '3.1.0', 'fixed_version' : '3.2.0', 'plugin' : jenkins_plugin_mappings['Bitbucket Server Integration Plugin'] }
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

var flags = {'xsrf':TRUE, 'xss':TRUE};
vcf::jenkins::plugin::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:flags);
