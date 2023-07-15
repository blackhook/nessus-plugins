#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155735);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2021-21628",
    "CVE-2021-21629",
    "CVE-2021-21630",
    "CVE-2021-21631",
    "CVE-2021-21632",
    "CVE-2021-21633",
    "CVE-2021-21634",
    "CVE-2021-21635",
    "CVE-2021-21636",
    "CVE-2021-21637",
    "CVE-2021-21638"
  );

  script_name(english:"Jenkins Plugins Multiple Vulnerabilities (Jenkins Security Advisory 2021-03-30)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the versions of Jenkins plugins running on the remote web server are
Jenkins Build With Parameters Plugin prior to 1.5.1, Cloud Statistics Plugin prior to 0.27, Extra Columns Plugin prior
to 1.23, Jabber (XMPP) notifier and control Plugin prior to 1.42, OWASP Dependency-Track Plugin prior to 3.1.1, REST
List Parameter Plugin prior to 1.3.1, or Team Foundation Server Plugin 5.157.1 or earlier. They are, therefore, affected
by multiple vulnerabilities:

  - Jenkins Build With Parameters Plugin 1.5 and earlier does not escape parameter names and descriptions,
    resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers with Job/Configure
    permission. (CVE-2021-21628)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Build With Parameters Plugin 1.5 and earlier
    allows attackers to build a project with attacker-specified parameters. (CVE-2021-21629)

  - Jenkins Extra Columns Plugin 1.22 and earlier does not escape parameter values in the build parameters
    column, resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers with
    Job/Configure permission. (CVE-2021-21630)

  - Jenkins Cloud Statistics Plugin 0.26 and earlier does not perform a permission check in an HTTP endpoint,
    allowing attackers with Overall/Read permission and knowledge of random activity IDs to view related
    provisioning exception error messages. (CVE-2021-21631)

  - A missing permission check in Jenkins OWASP Dependency-Track Plugin 3.1.0 and earlier allows attackers
    with Overall/Read permission to connect to an attacker-specified URL, capturing credentials stored in
    Jenkins. (CVE-2021-21632)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins OWASP Dependency-Track Plugin 3.1.0 and
    earlier allows attackers to connect to an attacker-specified URL, capturing credentials stored in Jenkins.
    (CVE-2021-21633)

  - Jenkins Jabber (XMPP) notifier and control Plugin 1.41 and earlier stores passwords unencrypted in its
    global configuration file on the Jenkins controller where they can be viewed by users with access to the
    Jenkins controller file system. (CVE-2021-21634)

  - Jenkins REST List Parameter Plugin 1.3.0 and earlier does not escape a parameter name reference in
    embedded JavaScript, resulting in a stored cross-site scripting (XSS) vulnerability exploitable by
    attackers with Job/Configure permission. (CVE-2021-21635)

  - A missing permission check in Jenkins Team Foundation Server Plugin 5.157.1 and earlier allows attackers
    with Overall/Read permission to enumerate credentials ID of credentials stored in Jenkins.
    (CVE-2021-21636)

  - A missing permission check in Jenkins Team Foundation Server Plugin 5.157.1 and earlier allows attackers
    with Overall/Read permission to connect to an attacker-specified URL using attacker-specified credentials
    IDs obtained through another method, capturing credentials stored in Jenkins. (CVE-2021-21637)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2021-03-30");
  script_set_attribute(attribute:"solution", value:
"Upgrade REST List Parameter Plugin to version 1.3.1 or later, OWASP Dependency-Track Plugin to version 3.1.1 or later,
Jabber (XMPP) notifier and control Plugin to version 1.42 or later, Extra Columns Plugin to version 1.23 or later, Cloud
Statistics Plugin to version 0.27 or later, and Build With Parameters Plugin to version 1.5.1 or later.

See vendor advisory for Team Foundation Server plugin.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21638");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_plugins_detect.nbin", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf_extras.inc');

var plugin_list_and_constraints = [
  { 'plugin' : 'Build With Parameters',                             'fixed_version' : '1.5.1' },
  { 'plugin' : 'Cloud Statistics Plugin',                           'fixed_version' : '0.27'  },
  { 'plugin' : 'Extra Columns Plugin',                              'fixed_version' : '1.23'  },
  { 'plugin' : 'Jenkins Jabber (XMPP) notifier and control plugin', 'fixed_version' : '1.42'  },
  { 'plugin' : 'OWASP Dependency-Track Plugin',                     'fixed_version' : '3.1.1' },
  { 'plugin' : 'REST List Parameter',                               'fixed_version' : '1.3.1' },
  { 'plugin' : 'Team Foundation Server Plug-in', 'max_version' : '5.157.1', 'fixed_display' : 'See vendor advisory' }
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:plugin_list_and_constraints);

vcf::jenkins::plugin::check_version_and_report(
  app_info:app_info,
  constraints:plugin_list_and_constraints,
  severity:SECURITY_WARNING,
  flags:{'xsrf':TRUE, 'xss':TRUE}
);
