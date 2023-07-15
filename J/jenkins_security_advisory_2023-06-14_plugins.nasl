#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177394);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id(
    "CVE-2023-32261",
    "CVE-2023-32262",
    "CVE-2023-35142",
    "CVE-2023-35143",
    "CVE-2023-35144",
    "CVE-2023-35145",
    "CVE-2023-35146",
    "CVE-2023-35147",
    "CVE-2023-35148",
    "CVE-2023-35149"
  );
  script_xref(name:"JENKINS", value:"2023-06-14");

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2023-06-14)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - Jenkins Checkmarx Plugin 2022.4.3 and earlier disables SSL/TLS validation for connections to the Checkmarx
    server by default. (CVE-2023-35142)

  - Jenkins Maven Repository Server Plugin 1.10 and earlier does not escape the versions of build artifacts on
    the Build Artifacts As Maven Repository page, resulting in a stored cross-site scripting (XSS)
    vulnerability exploitable by attackers able to control maven project versions in `pom.xml`.
    (CVE-2023-35143)

  - Jenkins Maven Repository Server Plugin 1.10 and earlier does not escape project and build display names on
    the Build Artifacts As Maven Repository page, resulting in a stored cross-site scripting (XSS)
    vulnerability. (CVE-2023-35144)

  - Jenkins Sonargraph Integration Plugin 5.0.1 and earlier does not escape the file path and the project name
    for the Log file field form validation, resulting in a stored cross-site scripting vulnerability
    exploitable by attackers with Item/Configure permission. (CVE-2023-35145)

  - Jenkins Template Workflows Plugin 41.v32d86a_313b_4a and earlier does not escape names of jobs used as
    buildings blocks for Template Workflow Job, resulting in a stored cross-site scripting (XSS) vulnerability
    exploitable by attackers able to create jobs. (CVE-2023-35146)

  - Jenkins AWS CodeCommit Trigger Plugin 3.0.12 and earlier does not restrict the AWS SQS queue name path
    parameter in an HTTP endpoint, allowing attackers with Item/Read permission to obtain the contents of
    arbitrary files on the Jenkins controller file system. (CVE-2023-35147)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Digital.ai App Management Publisher Plugin
    2.6 and earlier allows attackers to connect to an attacker-specified URL, capturing credentials stored in
    Jenkins. (CVE-2023-35148)

  - A missing permission check in Jenkins Digital.ai App Management Publisher Plugin 2.6 and earlier allows
    attackers with Overall/Read permission to connect to an attacker-specified URL, capturing credentials
    stored in Jenkins. (CVE-2023-35149)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2023-06-14");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - AWS CodeCommit Trigger Plugin: See vendor advisory
  - Checkmarx Plugin to version 2023.2.6 or later
  - Digital.ai App Management Publisher Plugin: See vendor advisory
  - Dimensions Plugin to version 0.9.3.1 or later
  - Maven Repository Server Plugin: See vendor advisory
  - Sonargraph Integration Plugin: See vendor advisory
  - Team Concert Plugin to version 2.4.2 or later
  - Template Workflows Plugin: See vendor advisory

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-35148");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-35142");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_plugins_detect.nbin", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');
include('jenkins_plugin_mappings.inc');

var constraints = [
    {'max_version' : '3.0.12', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['AWS CodeCommit Trigger Plugin']},
    {'max_version' : '2022.4.3', 'fixed_version' : '2023.2.6', 'plugin' : jenkins_plugin_mappings['Checkmarx Plugin']},
    {'max_version' : '2.6', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['Digital.ai App Management Publisher Plugin']},
    {'max_version' : '0.9.3', 'fixed_version' : '0.9.3.1', 'plugin' : jenkins_plugin_mappings['Dimensions Plugin']},
    {'max_version' : '1.10', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['Maven Repository Server Plugin']},
    {'max_version' : '5.0.1', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['Sonargraph Integration Plugin']},
    {'max_version' : '2.4.1', 'fixed_version' : '2.4.2', 'plugin' : jenkins_plugin_mappings['Team Concert Plugin']},
    {'max_version' : '41', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['Template Workflows Plugin']}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE, 'xss':TRUE}
);
