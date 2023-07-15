#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156930);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2022-20612",
    "CVE-2022-20613",
    "CVE-2022-20614",
    "CVE-2022-20615",
    "CVE-2022-20616",
    "CVE-2022-20617",
    "CVE-2022-20618",
    "CVE-2022-20619",
    "CVE-2022-20620",
    "CVE-2022-20621",
    "CVE-2022-23105",
    "CVE-2022-23106",
    "CVE-2022-23107",
    "CVE-2022-23108",
    "CVE-2022-23109",
    "CVE-2022-23110",
    "CVE-2022-23111",
    "CVE-2022-23112",
    "CVE-2022-23113",
    "CVE-2022-23114",
    "CVE-2022-23115",
    "CVE-2022-23116",
    "CVE-2022-23117",
    "CVE-2022-23118"
  );
  script_xref(name:"IAVA", value:"2022-A-0027-S");
  script_xref(name:"IAVA", value:"2022-A-0084");

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2022-01-12)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its their self-reported version number, the version of Jenkins plugins running on the remote web server are
Jenkins Active Directory Plugin prior to 2.25.1, Badge Plugin prior to 1.9.1, Bitbucket Branch Source Plugin prior to
746., Configuration as Code Plugin prior to 1.55.1, Conjur Secrets Plugin 1.0.9 or earlier, Credentials Binding Plugin
prior to 1.27.1, Debian Package Builder Plugin 1.6.11 or earlier, Docker Commons Plugin prior to 1.18, HashiCorp Vault
Plugin prior to 3.8.0, Mailer Plugin prior to 408., Matrix Project Plugin prior to 1.20, Metrics Plugin prior to
4.0.2.8.1, Publish Over SSH Plugin 1.22 or earlier, SSH Agent Plugin prior to 1.23.2, Warnings Next Generation Plugin
prior to 9.10.3, batch task Plugin 1.19 or earlier. They are, therefore, affected by multiple vulnerabilities:

  - A cross-site request forgery (CSRF) vulnerability in Jenkins 2.329 and earlier, LTS 2.319.1 and earlier
    allows attackers to trigger build of job without parameters when no security realm is set.
    (CVE-2022-20612)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Mailer Plugin 391.ve4a_38c1b_cf4b_ and
    earlier allows attackers to use the DNS used by the Jenkins instance to resolve an attacker-specified
    hostname. (CVE-2022-20613)

  - A missing permission check in Jenkins Mailer Plugin 391.ve4a_38c1b_cf4b_ and earlier allows attackers with
    Overall/Read access to use the DNS used by the Jenkins instance to resolve an attacker-specified hostname.
    (CVE-2022-20614)

  - Jenkins Matrix Project Plugin 1.19 and earlier does not escape HTML metacharacters in node and label
    names, and label descriptions, resulting in a stored cross-site scripting (XSS) vulnerability exploitable
    by attackers with Agent/Configure permission. (CVE-2022-20615)

  - Jenkins Credentials Binding Plugin 1.27 and earlier does not perform a permission check in a method
    implementing form validation, allowing attackers with Overall/Read access to validate if a credential ID
    refers to a secret file credential and whether it's a zip file. (CVE-2022-20616)

  - Jenkins Docker Commons Plugin 1.17 and earlier does not sanitize the name of an image or a tag, resulting
    in an OS command execution vulnerability exploitable by attackers with Item/Configure permission or able
    to control the contents of a previously configured job's SCM repository. (CVE-2022-20617)

  - A missing permission check in Jenkins Bitbucket Branch Source Plugin 737.vdf9dc06105be and earlier allows
    attackers with Overall/Read access to enumerate credentials IDs of credentials stored in Jenkins.
    (CVE-2022-20618)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Bitbucket Branch Source Plugin
    737.vdf9dc06105be and earlier allows attackers to connect to an attacker-specified URL using attacker-
    specified credentials IDs obtained through another method, capturing credentials stored in Jenkins.
    (CVE-2022-20619)

  - Missing permission checks in Jenkins SSH Agent Plugin 1.23 and earlier allows attackers with Overall/Read
    access to enumerate credentials IDs of credentials stored in Jenkins. (CVE-2022-20620)

  - Jenkins Metrics Plugin 4.0.2.8 and earlier stores an access key unencrypted in its global configuration
    file on the Jenkins controller where it can be viewed by users with access to the Jenkins controller file
    system. (CVE-2022-20621)

  - Jenkins Active Directory Plugin 2.25 and earlier does not encrypt the transmission of data between the
    Jenkins controller and Active Directory servers in most configurations. (CVE-2022-23105)

  - Jenkins Configuration as Code Plugin 1.55 and earlier used a non-constant time comparison function when
    validating an authentication token allowing attackers to use statistical methods to obtain a valid
    authentication token. (CVE-2022-23106)

  - Jenkins Warnings Next Generation Plugin 9.10.2 and earlier does not restrict the name of a file when
    configuring custom ID, allowing attackers with Item/Configure permission to write and read specific files
    with a hard-coded suffix on the Jenkins controller file system. (CVE-2022-23107)

  - Jenkins Badge Plugin 1.9 and earlier does not escape the description and does not check for allowed
    protocols when creating a badge, resulting in a stored cross-site scripting (XSS) vulnerability
    exploitable by attackers with Item/Configure permission. (CVE-2022-23108)

  - Jenkins HashiCorp Vault Plugin 3.7.0 and earlier does not mask Vault credentials in Pipeline build logs or
    in Pipeline step descriptions when Pipeline: Groovy Plugin 2.85 or later is installed. (CVE-2022-23109)

  - Jenkins Publish Over SSH Plugin 1.22 and earlier does not escape the SSH server name, resulting in a
    stored cross-site scripting (XSS) vulnerability exploitable by attackers with Overall/Administer
    permission. (CVE-2022-23110)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Publish Over SSH Plugin 1.22 and earlier
    allows attackers to connect to an attacker-specified SSH server using attacker-specified credentials.
    (CVE-2022-23111)

  - A missing permission check in Jenkins Publish Over SSH Plugin 1.22 and earlier allows attackers with
    Overall/Read access to connect to an attacker-specified SSH server using attacker-specified credentials.
    (CVE-2022-23112)

  - Jenkins Publish Over SSH Plugin 1.22 and earlier performs a validation of the file name specifying whether
    it is present or not, resulting in a path traversal vulnerability allowing attackers with Item/Configure
    permission to discover the name of the Jenkins controller files. (CVE-2022-23113)

  - Jenkins Publish Over SSH Plugin 1.22 and earlier stores password unencrypted in its global configuration
    file on the Jenkins controller where it can be viewed by users with access to the Jenkins controller file
    system. (CVE-2022-23114)

  - Cross-site request forgery (CSRF) vulnerabilities in Jenkins batch task Plugin 1.19 and earlier allows
    attackers with Overall/Read access to retrieve logs, build or delete a batch task. (CVE-2022-23115)

  - Jenkins Conjur Secrets Plugin 1.0.9 and earlier implements functionality that allows attackers able to
    control agent processes to decrypt secrets stored in Jenkins obtained through another method.
    (CVE-2022-23116)

  - Jenkins Conjur Secrets Plugin 1.0.9 and earlier implements functionality that allows attackers able to
    control agent processes to retrieve all username/password credentials stored on the Jenkins controller.
    (CVE-2022-23117)

  - Jenkins Debian Package Builder Plugin 1.6.11 and earlier implements functionality that allows agents to
    invoke command-line `git` at an attacker-specified path on the controller, allowing attackers able to
    control agent processes to invoke arbitrary OS commands on the controller. (CVE-2022-23118)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2022-01-12");
  script_set_attribute(attribute:"solution", value:
"Upgrade Warnings Next Generation Plugin to version 9.10.3 or later, SSH Agent Plugin to version 1.23.2 or later, Metrics
Plugin to version 4.0.2.8.1 or later, Matrix Project Plugin to version 1.20 or later, Mailer Plugin to version 408. or
later, HashiCorp Vault Plugin to version 3.8.0 or later, Docker Commons Plugin to version 1.18 or later, Credentials
Binding Plugin to version 1.27.1 or later, Configuration as Code Plugin to version 1.55.1 or later, Bitbucket Branch
Source Plugin to version 746. or later, Badge Plugin to version 1.9.1 or later, Active Directory Plugin to version
2.25.1 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23118");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'max_version' : '1.19', 'plugin' : 'Jenkins batch task plugin', 'fixed_display' : 'See vendor advisory' },
  { 'max_version' : '9.10.2', 'fixed_version' : '9.10.3', 'plugin' : 'Warnings Next Generation Plugin' },
  { 'max_version' : '1.23', 'fixed_version' : '1.23.2', 'plugin' : 'SSH Agent Plugin' },
  { 'max_version' : '1.22', 'plugin' : 'Publish Over SSH', 'fixed_display' : 'See vendor advisory' },
  { 'max_version' : '4.0.2.8', 'fixed_version' : '4.0.2.8.1', 'plugin' : 'Metrics Plugin' },
  { 'max_version' : '1.19', 'fixed_version' : '1.20', 'plugin' : 'Matrix Project Plugin' },
  { 'max_version' : '391.', 'fixed_version' : '408.', 'plugin' : 'Jenkins Mailer Plugin' },
  { 'max_version' : '3.7.0', 'fixed_version' : '3.8.0', 'plugin' : 'HashiCorp Vault Plugin' },
  { 'max_version' : '1.17', 'fixed_version' : '1.18', 'plugin' : 'Docker Commons Plugin' },
  { 'max_version' : '1.6.11', 'plugin' : 'Debian Package Builder', 'fixed_display' : 'See vendor advisory' },
  { 'max_version' : '1.27', 'fixed_version' : '1.27.1', 'plugin' : 'Credentials Binding Plugin' },
  { 'max_version' : '1.0.9', 'plugin' : 'Conjur Secrets Plugin', 'fixed_display' : 'See vendor advisory' },
  { 'max_version' : '1.55', 'fixed_version' : '1.55.1', 'plugin' : 'Configuration as Code Plugin' },
  { 'max_version' : '737.', 'fixed_version' : '746.', 'plugin' : 'Bitbucket Branch Source Plugin' },
  { 'max_version' : '1.9', 'fixed_version' : '1.9.1', 'plugin' : 'Badge' },
  { 'max_version' : '2.25', 'fixed_version' : '2.25.1', 'plugin' : 'Jenkins Active Directory plugin' }
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

var flags = {'xsrf':TRUE, 'xss':TRUE};
vcf::jenkins::plugin::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:flags);
