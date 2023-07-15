##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162315);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/17");

  script_cve_id(
    "CVE-2022-30945",
    "CVE-2022-30946",
    "CVE-2022-30947",
    "CVE-2022-30948",
    "CVE-2022-30949",
    "CVE-2022-30950",
    "CVE-2022-30951",
    "CVE-2022-30952",
    "CVE-2022-30953",
    "CVE-2022-30954",
    "CVE-2022-30955",
    "CVE-2022-30956",
    "CVE-2022-30957",
    "CVE-2022-30958",
    "CVE-2022-30959",
    "CVE-2022-30960",
    "CVE-2022-30961",
    "CVE-2022-30962",
    "CVE-2022-30963",
    "CVE-2022-30964",
    "CVE-2022-30965",
    "CVE-2022-30966",
    "CVE-2022-30967",
    "CVE-2022-30968",
    "CVE-2022-30969",
    "CVE-2022-30970",
    "CVE-2022-30971",
    "CVE-2022-30972"
  );

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2022-05-17)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - Jenkins Pipeline: Groovy Plugin 2689.v434009a_31b_f1 and earlier allows loading any Groovy source files on
    the classpath of Jenkins and Jenkins plugins in sandboxed pipelines. (CVE-2022-30945)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Script Security Plugin 1158.v7c1b_73a_69a_08
    and earlier allows attackers to have Jenkins send an HTTP request to an attacker-specified webserver.
    (CVE-2022-30946)

  - Jenkins Git Plugin 4.11.1 and earlier allows attackers able to configure pipelines to check out some SCM
    repositories stored on the Jenkins controller's file system using local paths as SCM URLs, obtaining
    limited information about other projects' SCM contents. (CVE-2022-30947)

  - Jenkins Mercurial Plugin 2.16 and earlier allows attackers able to configure pipelines to check out some
    SCM repositories stored on the Jenkins controller's file system using local paths as SCM URLs, obtaining
    limited information about other projects' SCM contents. (CVE-2022-30948)

  - Jenkins REPO Plugin 1.14.0 and earlier allows attackers able to configure pipelines to check out some SCM
    repositories stored on the Jenkins controller's file system using local paths as SCM URLs, obtaining
    limited information about other projects' SCM contents. (CVE-2022-30949)

  - Jenkins WMI Windows Agents Plugin 1.8 and earlier includes the Windows Remote Command library which has a
    buffer overflow vulnerability that may allow users able to connect to a named pipe to execute commands on
    the Windows agent machine. (CVE-2022-30950)

  - Jenkins WMI Windows Agents Plugin 1.8 and earlier includes the Windows Remote Command library does not
    implement access control, potentially allowing users to start processes even if they're not allowed to log
    in. (CVE-2022-30951)

  - Jenkins Pipeline SCM API for Blue Ocean Plugin 1.25.3 and earlier allows attackers with Job/Configure
    permission to access credentials with attacker-specified IDs stored in the private per-user credentials
    stores of any attacker-specified user in Jenkins. (CVE-2022-30952)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Blue Ocean Plugin 1.25.3 and earlier allows
    attackers to connect to an attacker-specified HTTP server. (CVE-2022-30953)

  - Jenkins Blue Ocean Plugin 1.25.3 and earlier does not perform a permission check in several HTTP
    endpoints, allowing attackers with Overall/Read permission to connect to an attacker-specified HTTP
    server. (CVE-2022-30954)

  - Jenkins GitLab Plugin 1.5.31 and earlier does not perform a permission check in an HTTP endpoint, allowing
    attackers with Overall/Read permission to enumerate credentials IDs of credentials stored in Jenkins.
    (CVE-2022-30955)

  - Jenkins Rundeck Plugin 3.6.10 and earlier does not restrict URL schemes in Rundeck webhook submissions,
    resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers able to submit
    crafted Rundeck webhook payloads. (CVE-2022-30956)

  - A missing permission check in Jenkins SSH Plugin 2.6.1 and earlier allows attackers with Overall/Read
    permission to enumerate credentials IDs of credentials stored in Jenkins. (CVE-2022-30957)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins SSH Plugin 2.6.1 and earlier allows attackers
    to connect to an attacker-specified SSH server using attacker-specified credentials IDs obtained through
    another method, capturing credentials stored in Jenkins. (CVE-2022-30958)

  - A missing permission check in Jenkins SSH Plugin 2.6.1 and earlier allows attackers with Overall/Read
    permission to connect to an attacker-specified SSH server using attacker-specified credentials IDs
    obtained through another method, capturing credentials stored in Jenkins. (CVE-2022-30959)

  - Jenkins Application Detector Plugin 1.0.8 and earlier does not escape the name of Chois Application
    Version parameters on views displaying parameters, resulting in a stored cross-site scripting (XSS)
    vulnerability exploitable by attackers with Item/Configure permission. (CVE-2022-30960)

  - Jenkins Autocomplete Parameter Plugin 1.1 and earlier does not escape the name of Dropdown Autocomplete
    and Auto Complete String parameters on views displaying parameters, resulting in a stored cross-site
    scripting (XSS) vulnerability exploitable by attackers with Item/Configure permission. (CVE-2022-30961)

  - Jenkins Global Variable String Parameter Plugin 1.2 and earlier does not escape the name and description
    of Global Variable String parameters on views displaying parameters, resulting in a stored cross-site
    scripting (XSS) vulnerability exploitable by attackers with Item/Configure permission. (CVE-2022-30962)

  - Jenkins JDK Parameter Plugin 1.0 and earlier does not escape the name and description of JDK parameters on
    views displaying parameters, resulting in a stored cross-site scripting (XSS) vulnerability exploitable by
    attackers with Item/Configure permission. (CVE-2022-30963)

  - Jenkins Multiselect parameter Plugin 1.3 and earlier does not escape the name and description of
    Multiselect parameters on views displaying parameters, resulting in a stored cross-site scripting (XSS)
    vulnerability exploitable by attackers with Item/Configure permission. (CVE-2022-30964)

  - Jenkins Promoted Builds (Simple) Plugin 1.9 and earlier does not escape the name and description of
    Promotion Level parameters on views displaying parameters, resulting in a stored cross-site scripting
    (XSS) vulnerability exploitable by attackers with Item/Configure permission. (CVE-2022-30965)

  - Jenkins Random String Parameter Plugin 1.0 and earlier does not escape the name and description of Random
    String parameters on views displaying parameters, resulting in a stored cross-site scripting (XSS)
    vulnerability exploitable by attackers with Item/Configure permission. (CVE-2022-30966)

  - Jenkins Selection tasks Plugin 1.0 and earlier does not escape the name and description of Script
    Selection task variable parameters on views displaying parameters, resulting in a stored cross-site
    scripting (XSS) vulnerability exploitable by attackers with Item/Configure permission. (CVE-2022-30967)

  - Jenkins vboxwrapper Plugin 1.3 and earlier does not escape the name and description of VBox node
    parameters on views displaying parameters, resulting in a stored cross-site scripting (XSS) vulnerability
    exploitable by attackers with Item/Configure permission. (CVE-2022-30968)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Autocomplete Parameter Plugin 1.1 and earlier
    allows attackers to execute arbitrary code without sandbox protection if the victim is an administrator.
    (CVE-2022-30969)

  - Jenkins Autocomplete Parameter Plugin 1.1 and earlier references Dropdown Autocomplete parameter and Auto
    Complete String parameter names in an unsafe manner from Javascript embedded in view definitions,
    resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers with
    Item/Configure permission. (CVE-2022-30970)

  - Jenkins Storable Configs Plugin 1.0 and earlier does not configure its XML parser to prevent XML external
    entity (XXE) attacks. (CVE-2022-30971)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Storable Configs Plugin 1.0 and earlier
    allows attackers to have Jenkins parse a local XML file (e.g., archived artifacts) that uses external
    entities for extraction of secrets from the Jenkins controller or server-side request forgery.
    (CVE-2022-30972)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2022-05-17");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - Application Detector Plugin to version 1.0.9 or later
  - Autocomplete Parameter Plugin: See vendor advisory
  - Blue Ocean Plugin to version 1.25.4 or later
  - Git Plugin to version 4.11.2 or later
  - GitLab Plugin to version 1.5.32 or later
  - Global Variable String Parameter Plugin: See vendor advisory
  - JDK Parameter Plugin: See vendor advisory
  - Mercurial Plugin to version 2.16.1 or later
  - Multiselect parameter Plugin to version 1.4 or later
  - Pipeline SCM API for Blue Ocean Plugin to version 1.25.4 or later
  - Pipeline: Groovy Plugin to version 2692.v76b_089ccd026 or later
  - Promoted Builds (Simple) Plugin: See vendor advisory
  - Random String Parameter Plugin: See vendor advisory
  - REPO Plugin to version 1.14.1 or later
  - Rundeck Plugin to version 3.6.11 or later
  - Script Security Plugin to version 1172.v35f6a_0b_8207e or later
  - Selection tasks Plugin: See vendor advisory
  - SSH Plugin: See vendor advisory
  - Storable Configs Plugin: See vendor advisory
  - vboxwrapper Plugin: See vendor advisory
  - WMI Windows Agents Plugin to version 1.8.1 or later

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30972");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
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
    {'max_version' : '1.0.8', 'fixed_version' : '1.0.9', 'plugin' : jenkins_plugin_mappings['Application Detector Plugin']},
    {'max_version' : '1.1', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['Autocomplete Parameter Plugin']},
    {'max_version' : '1.25.3', 'fixed_version' : '1.25.4', 'plugin' : jenkins_plugin_mappings['Blue Ocean Plugin']},
    {'max_version' : '4.11.1', 'fixed_version' : '4.11.2', 'plugin' : jenkins_plugin_mappings['Git Plugin']},
    {'max_version' : '1.5.31', 'fixed_version' : '1.5.32', 'plugin' : jenkins_plugin_mappings['GitLab Plugin']},
    {'max_version' : '1.2', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['Global Variable String Parameter Plugin']},
    {'max_version' : '1.0', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['JDK Parameter Plugin']},
    {'max_version' : '2.16', 'fixed_version' : '2.16.1', 'plugin' : jenkins_plugin_mappings['Mercurial Plugin']},
    {'max_version' : '1.3', 'fixed_version' : '1.4', 'plugin' : jenkins_plugin_mappings['Multiselect parameter Plugin']},
    {'max_version' : '1.25.3', 'fixed_version' : '1.25.4', 'plugin' : jenkins_plugin_mappings['Pipeline SCM API for Blue Ocean Plugin']},
    {'max_version' : '2689', 'fixed_version' : '2692', 'fixed_display' : '2692.v76b_089ccd026', 'plugin' : jenkins_plugin_mappings['Pipeline: Groovy Plugin']},
    {'max_version' : '1.9', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['Promoted Builds (Simple) Plugin']},
    {'max_version' : '1.0', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['Random String Parameter Plugin']},
    {'max_version' : '1.14.0', 'fixed_version' : '1.14.1', 'plugin' : jenkins_plugin_mappings['REPO Plugin']},
    {'max_version' : '3.6.10', 'fixed_version' : '3.6.11', 'plugin' : jenkins_plugin_mappings['Rundeck Plugin']},
    {'max_version' : '1158', 'fixed_version' : '1172', 'fixed_display' : '1172.v35f6a_0b_8207e', 'plugin' : jenkins_plugin_mappings['Script Security Plugin']},
    {'max_version' : '1.0', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['Selection tasks Plugin']},
    {'max_version' : '2.6.1', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['SSH Plugin']},
    {'max_version' : '1.0', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['Storable Configs Plugin']},
    {'max_version' : '1.3', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['vboxwrapper Plugin']},
    {'max_version' : '1.8', 'fixed_version' : '1.8.1', 'plugin' : jenkins_plugin_mappings['WMI Windows Agents Plugin']}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xsrf':TRUE, 'xss':TRUE}
);
