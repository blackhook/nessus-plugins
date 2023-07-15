#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172085);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/06");

  script_cve_id(
    "CVE-2022-43401",
    "CVE-2022-43404",
    "CVE-2022-43405",
    "CVE-2022-43406",
    "CVE-2022-43407",
    "CVE-2022-43408",
    "CVE-2022-43409",
    "CVE-2022-43410",
    "CVE-2022-43411",
    "CVE-2022-43412",
    "CVE-2022-43413",
    "CVE-2022-43414",
    "CVE-2022-43415",
    "CVE-2022-43416",
    "CVE-2022-43417",
    "CVE-2022-43418",
    "CVE-2022-43419",
    "CVE-2022-43420",
    "CVE-2022-43421",
    "CVE-2022-43422",
    "CVE-2022-43423",
    "CVE-2022-43424",
    "CVE-2022-43425",
    "CVE-2022-43426",
    "CVE-2022-43427",
    "CVE-2022-43428",
    "CVE-2022-43429",
    "CVE-2022-43430",
    "CVE-2022-43431",
    "CVE-2022-43432",
    "CVE-2022-43433",
    "CVE-2022-43434",
    "CVE-2022-43435"
  );

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2022-10-19)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - A sandbox bypass vulnerability involving various casts performed implicitly by the Groovy language runtime
    in Jenkins Script Security Plugin 1183.v774b_0b_0a_a_451 and earlier allows attackers with permission to
    define and run sandboxed scripts, including Pipelines, to bypass the sandbox protection and execute
    arbitrary code in the context of the Jenkins controller JVM. (CVE-2022-43401)

  - A sandbox bypass vulnerability involving crafted constructor bodies and calls to sandbox-generated
    synthetic constructors in Jenkins Script Security Plugin 1183.v774b_0b_0a_a_451 and earlier allows
    attackers with permission to define and run sandboxed scripts, including Pipelines, to bypass the sandbox
    protection and execute arbitrary code in the context of the Jenkins controller JVM. (CVE-2022-43404)

  - A sandbox bypass vulnerability in Jenkins Pipeline: Groovy Libraries Plugin 612.v84da_9c54906d and earlier
    allows attackers with permission to define untrusted Pipeline libraries and to define and run sandboxed
    scripts, including Pipelines, to bypass the sandbox protection and execute arbitrary code in the context
    of the Jenkins controller JVM. (CVE-2022-43405)

  - A sandbox bypass vulnerability in Jenkins Pipeline: Deprecated Groovy Libraries Plugin 583.vf3b_454e43966
    and earlier allows attackers with permission to define untrusted Pipeline libraries and to define and run
    sandboxed scripts, including Pipelines, to bypass the sandbox protection and execute arbitrary code in the
    context of the Jenkins controller JVM. (CVE-2022-43406)

  - Jenkins Pipeline: Input Step Plugin 451.vf1a_a_4f405289 and earlier does not restrict or sanitize the
    optionally specified ID of the 'input' step, which is used for the URLs that process user interactions for
    the given 'input' step (proceed or abort) and is not correctly encoded, allowing attackers able to
    configure Pipelines to have Jenkins build URLs from 'input' step IDs that would bypass the CSRF protection
    of any target URL in Jenkins when the 'input' step is interacted with. (CVE-2022-43407)

  - Jenkins Pipeline: Stage View Plugin 2.26 and earlier does not correctly encode the ID of 'input' steps
    when using it to generate URLs to proceed or abort Pipeline builds, allowing attackers able to configure
    Pipelines to specify 'input' step IDs resulting in URLs that would bypass the CSRF protection of any
    target URL in Jenkins. (CVE-2022-43408)

  - Jenkins Pipeline: Supporting APIs Plugin 838.va_3a_087b_4055b and earlier does not sanitize or properly
    encode URLs of hyperlinks sending POST requests in build logs, resulting in a stored cross-site scripting
    (XSS) vulnerability exploitable by attackers able to create Pipelines. (CVE-2022-43409)

  - Jenkins Mercurial Plugin 1251.va_b_121f184902 and earlier provides information about which jobs were
    triggered or scheduled for polling through its webhook endpoint, including jobs the user has no permission
    to access. (CVE-2022-43410)

  - Jenkins GitLab Plugin 1.5.35 and earlier uses a non-constant time comparison function when checking
    whether the provided and expected webhook token are equal, potentially allowing attackers to use
    statistical methods to obtain a valid webhook token. (CVE-2022-43411)

  - Jenkins Generic Webhook Trigger Plugin 1.84.1 and earlier uses a non-constant time comparison function
    when checking whether the provided and expected webhook token are equal, potentially allowing attackers to
    use statistical methods to obtain a valid webhook token. (CVE-2022-43412)

  - Jenkins Job Import Plugin 3.5 and earlier does not perform a permission check in an HTTP endpoint,
    allowing attackers with Overall/Read permission to enumerate credentials IDs of credentials stored in
    Jenkins. (CVE-2022-43413)

  - Jenkins NUnit Plugin 0.27 and earlier implements an agent-to-controller message that parses files inside a
    user-specified directory as test results, allowing attackers able to control agent processes to obtain
    test results from files in an attacker-specified directory on the Jenkins controller. (CVE-2022-43414)

  - Jenkins REPO Plugin 1.15.0 and earlier does not configure its XML parser to prevent XML external entity
    (XXE) attacks. (CVE-2022-43415)

  - Jenkins Katalon Plugin 1.0.32 and earlier implements an agent/controller message that does not limit where
    it can be executed and allows invoking Katalon with configurable arguments, allowing attackers able to
    control agent processes to invoke Katalon on the Jenkins controller with attacker-controlled version,
    install location, and arguments, and attackers additionally able to create files on the Jenkins controller
    (e.g., attackers with Item/Configure permission could archive artifacts) to invoke arbitrary OS commands.
    (CVE-2022-43416)

  - Jenkins Katalon Plugin 1.0.32 and earlier does not perform permission checks in several HTTP endpoints,
    allowing attackers with Overall/Read permission to connect to an attacker-specified URL using attacker-
    specified credentials IDs obtained through another method, capturing credentials stored in Jenkins.
    (CVE-2022-43417)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Katalon Plugin 1.0.33 and earlier allows
    attackers to connect to an attacker-specified URL using attacker-specified credentials IDs obtained
    through another method, capturing credentials stored in Jenkins. (CVE-2022-43418)

  - Jenkins Katalon Plugin 1.0.32 and earlier stores API keys unencrypted in job config.xml files on the
    Jenkins controller where they can be viewed by users with Extended Read permission, or access to the
    Jenkins controller file system. (CVE-2022-43419)

  - Jenkins Contrast Continuous Application Security Plugin 3.9 and earlier does not escape data returned from
    the Contrast service when generating a report, resulting in a stored cross-site scripting (XSS)
    vulnerability exploitable by attackers able to control or modify Contrast service API responses.
    (CVE-2022-43420)

  - A missing permission check in Jenkins Tuleap Git Branch Source Plugin 3.2.4 and earlier allows
    unauthenticated attackers to trigger Tuleap projects whose configured repository matches the attacker-
    specified value. (CVE-2022-43421)

  - Jenkins Compuware Topaz Utilities Plugin 1.0.8 and earlier implements an agent/controller message that
    does not limit where it can be executed, allowing attackers able to control agent processes to obtain the
    values of Java system properties from the Jenkins controller process. (CVE-2022-43422)

  - Jenkins Compuware Source Code Download for Endevor, PDS, and ISPW Plugin 2.0.12 and earlier implements an
    agent/controller message that does not limit where it can be executed, allowing attackers able to control
    agent processes to obtain the values of Java system properties from the Jenkins controller process.
    (CVE-2022-43423)

  - Jenkins Compuware Xpediter Code Coverage Plugin 1.0.7 and earlier implements an agent/controller message
    that does not limit where it can be executed, allowing attackers able to control agent processes to obtain
    the values of Java system properties from the Jenkins controller process. (CVE-2022-43424)

  - Jenkins Custom Checkbox Parameter Plugin 1.4 and earlier does not escape the name and description of
    Custom Checkbox Parameter parameters on views displaying parameters, resulting in a stored cross-site
    scripting (XSS) vulnerability exploitable by attackers with Item/Configure permission. (CVE-2022-43425)

  - Jenkins S3 Explorer Plugin 1.0.8 and earlier does not mask the AWS_SECRET_ACCESS_KEY form field,
    increasing the potential for attackers to observe and capture it. (CVE-2022-43426)

  - Jenkins Compuware Topaz for Total Test Plugin 2.4.8 and earlier does not perform permission checks in
    several HTTP endpoints, allowing attackers with Overall/Read permission to enumerate credentials IDs of
    credentials stored in Jenkins. (CVE-2022-43427)

  - Jenkins Compuware Topaz for Total Test Plugin 2.4.8 and earlier implements an agent/controller message
    that does not limit where it can be executed, allowing attackers able to control agent processes to obtain
    the values of Java system properties from the Jenkins controller process. (CVE-2022-43428)

  - Jenkins Compuware Topaz for Total Test Plugin 2.4.8 and earlier implements an agent/controller message
    that does not limit where it can be executed, allowing attackers able to control agent processes to read
    arbitrary files on the Jenkins controller file system. (CVE-2022-43429)

  - Jenkins Compuware Topaz for Total Test Plugin 2.4.8 and earlier does not configure its XML parser to
    prevent XML external entity (XXE) attacks. (CVE-2022-43430)

  - Jenkins Compuware Strobe Measurement Plugin 1.0.1 and earlier does not perform a permission check in an
    HTTP endpoint, allowing attackers with Overall/Read permission to enumerate credentials IDs of credentials
    stored in Jenkins. (CVE-2022-43431)

  - Jenkins XFramium Builder Plugin 1.0.22 and earlier programmatically disables Content-Security-Policy
    protection for user-generated content in workspaces, archived artifacts, etc. that Jenkins offers for
    download. (CVE-2022-43432)

  - Jenkins ScreenRecorder Plugin 0.7 and earlier programmatically disables Content-Security-Policy protection
    for user-generated content in workspaces, archived artifacts, etc. that Jenkins offers for download.
    (CVE-2022-43433)

  - Jenkins NeuVector Vulnerability Scanner Plugin 1.20 and earlier programmatically disables Content-
    Security-Policy protection for user-generated content in workspaces, archived artifacts, etc. that Jenkins
    offers for download. (CVE-2022-43434)

  - Jenkins 360 FireLine Plugin 1.7.2 and earlier programmatically disables Content-Security-Policy protection
    for user-generated content in workspaces, archived artifacts, etc. that Jenkins offers for download.
    (CVE-2022-43435)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2022-10-19");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - 360 FireLine Plugin: See vendor advisory
  - Compuware Source Code Download for Endevor, PDS, and ISPW Plugin to version 2.0.13 or later
  - Compuware Strobe Measurement Plugin: See vendor advisory
  - Compuware Topaz for Total Test Plugin: See vendor advisory
  - Compuware Topaz Utilities Plugin to version 1.0.9 or later
  - Compuware Xpediter Code Coverage Plugin to version 1.0.8 or later
  - Contrast Continuous Application Security Plugin to version 3.10 or later
  - Custom Checkbox Parameter Plugin: See vendor advisory
  - Generic Webhook Trigger Plugin to version 1.84.2 or later
  - GitLab Plugin to version 1.5.36 or later
  - Job Import Plugin to version 3.6 or later
  - Katalon Plugin to version 1.0.34 or later
  - Mercurial Plugin to version 1260.vdfb_723cdcc81 or later
  - NeuVector Vulnerability Scanner Plugin: See vendor advisory
  - NUnit Plugin to version 0.28 or later
  - Pipeline: Deprecated Groovy Libraries Plugin to version 588.v576c103a_ff86 or later
  - Pipeline: Groovy Libraries Plugin: See vendor advisory
  - Pipeline: Groovy Plugin to version 2803.v1a_f77ffcc773 or later
  - Pipeline: Input Step Plugin to version 456.vd8a_957db_5b_e9 or later
  - Pipeline: Stage View Plugin to version 2.27 or later
  - Pipeline: Supporting APIs Plugin to version 839.v35e2736cfd5c or later
  - REPO Plugin to version 1.16.0 or later
  - S3 Explorer Plugin: See vendor advisory
  - ScreenRecorder Plugin: See vendor advisory
  - Script Security Plugin to version 1184.v85d16b_d851b_3 or later
  - Tuleap Git Branch Source Plugin to version 3.2.5 or later
  - XFramium Builder Plugin: See vendor advisory

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-43407");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-43406");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_plugins_detect.nbin", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');
include('jenkins_plugin_mappings.inc');

var constraints = [
    {'max_version' : '1.7.2', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['360 FireLine Plugin']},
    {'max_version' : '2.0.12', 'fixed_version' : '2.0.13', 'plugin' : jenkins_plugin_mappings['Compuware Source Code Download for Endevor, PDS, and ISPW Plugin']},
    {'max_version' : '1.0.1', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['Compuware Strobe Measurement Plugin']},
    {'max_version' : '2.4.8', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['Compuware Topaz for Total Test Plugin']},
    {'max_version' : '1.0.8', 'fixed_version' : '1.0.9', 'plugin' : jenkins_plugin_mappings['Compuware Topaz Utilities Plugin']},
    {'max_version' : '1.0.7', 'fixed_version' : '1.0.8', 'plugin' : jenkins_plugin_mappings['Compuware Xpediter Code Coverage Plugin']},
    {'max_version' : '3.9', 'fixed_version' : '3.10', 'plugin' : jenkins_plugin_mappings['Contrast Continuous Application Security Plugin']},
    {'max_version' : '1.4', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['Custom Checkbox Parameter Plugin']},
    {'max_version' : '1.84.1', 'fixed_version' : '1.84.2', 'plugin' : jenkins_plugin_mappings['Generic Webhook Trigger Plugin']},
    {'max_version' : '1.5.35', 'fixed_version' : '1.5.36', 'plugin' : jenkins_plugin_mappings['GitLab Plugin']},
    {'max_version' : '3.5', 'fixed_version' : '3.6', 'plugin' : jenkins_plugin_mappings['Job Import Plugin']},
    {'min_version' : '1.0.33', 'fixed_version' : '1.0.34', 'plugin' : jenkins_plugin_mappings['Katalon Plugin']},
    {'max_version' : '1251', 'fixed_version' : '1260', 'fixed_display' : '1260.vdfb_723cdcc81', 'plugin' : jenkins_plugin_mappings['Mercurial Plugin']},
    {'max_version' : '1.20', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['NeuVector Vulnerability Scanner Plugin']},
    {'max_version' : '0.27', 'fixed_version' : '0.28', 'plugin' : jenkins_plugin_mappings['NUnit Plugin']},
    {'max_version' : '583', 'fixed_version' : '588', 'fixed_display' : '588.v576c103a_ff86', 'plugin' : jenkins_plugin_mappings['Pipeline: Deprecated Groovy Libraries Plugin']},
    {'max_version' : '612', 'fixed_version' : '612.614', 'fixed_display' : '613.v9c41a_160233f or 612.614.v48dcb_f62a_640', 'plugin' : jenkins_plugin_mappings['Pipeline: Groovy Libraries Plugin']},
    {'max_version' : '2802', 'fixed_version' : '2803', 'fixed_display' : '2803.v1a_f77ffcc773', 'plugin' : jenkins_plugin_mappings['Pipeline: Groovy Plugin']},
    {'max_version' : '451', 'fixed_version' : '456', 'fixed_display' : '456.vd8a_957db_5b_e9', 'plugin' : jenkins_plugin_mappings['Pipeline: Input Step Plugin']},
    {'max_version' : '2.26', 'fixed_version' : '2.27', 'plugin' : jenkins_plugin_mappings['Pipeline: Stage View Plugin']},
    {'max_version' : '838', 'fixed_version' : '839', 'fixed_display' : '839.v35e2736cfd5c', 'plugin' : jenkins_plugin_mappings['Pipeline: Supporting APIs Plugin']},
    {'max_version' : '1.15.0', 'fixed_version' : '1.16.0', 'plugin' : jenkins_plugin_mappings['REPO Plugin']},
    {'max_version' : '1.0.8', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['S3 Explorer Plugin']},
    {'max_version' : '0.7', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['ScreenRecorder Plugin']},
    {'max_version' : '1183', 'fixed_version' : '1184', 'fixed_display' : '1184.v85d16b_d851b_3', 'plugin' : jenkins_plugin_mappings['Script Security Plugin']},
    {'max_version' : '3.2.4', 'fixed_version' : '3.2.5', 'plugin' : jenkins_plugin_mappings['Tuleap Git Branch Source Plugin']},
    {'max_version' : '1.0.22', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['XFramium Builder Plugin']}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE, 'xss':TRUE}
);
