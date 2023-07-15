#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129169);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-1003000", "CVE-2019-1003001", "CVE-2019-1003002");
  script_bugtraq_id(106681);

  script_name(english:"Jenkins Security Advisory 2019-01-08 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Jenkins running on the remote web server has one or more plugins affected by following vulnerabilities:

  - A sandbox bypass vulnerability exists in Script Security Plugin 1.49 and earlier in
    src/main/java/org/jenkinsci/plugins/scriptsecurity/sandbox/groovy/GroovySandbox.java
    that allows attackers with the ability to provide sandboxed scripts to execute arbitrary
    code on the Jenkins master JVM.
    (CVE-2019-1003000)

  - A sandbox bypass vulnerability exists in Pipeline: Groovy Plugin 2.61 and earlier in
    src/main/java/org/jenkinsci/plugins/workflow/cps/CpsFlowDefinition.java,
    src/main/java/org/jenkinsci/plugins/workflow/cps/CpsGroovyShellFactory.java
    that allows attackers with Overall/Read permission to provide a pipeline script to an
    HTTP endpoint that can result in arbitrary code execution on the Jenkins master JVM.
    (CVE-2019-1003001)

  - A sandbox bypass vulnerability exists in Pipeline: Declarative Plugin 1.3.3 and earlier in
    pipeline-model-definition/src/main/groovy/org/jenkinsci/plugins/pipeline/modeldefinition/parser/Converter.groovy
    that allows attackers with Overall/Read permission to provide a pipeline script to an HTTP
    endpoint that can result in arbitrary code execution on the Jenkins master JVM.
    (CVE-2019-1003002)");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2019-01-08/");
  script_set_attribute(attribute:"solution", value:
"Refer to vendor advisory for details.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1003000");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Jenkins ACL Bypass and Metaprogramming RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_plugins_detect.nbin");
  script_require_keys("www/Jenkins");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('install_func.inc');


# list of plugins long names and their fixed versions
plugins = make_array(
'Pipeline: Declarative', '1.3.4.1',
'Pipeline: Groovy', '2.61.1',
'Script Security Plugin', '1.50'
);

app = 'Jenkins';
get_install_count(app_name:app, exit_if_zero:TRUE);

# Check if jenkins_plugins table exists
table = query_scratchpad("SELECT name FROM sqlite_master where type = 'table' and name = 'jenkins_plugins'");
if (empty_or_null(table)) exit(0, 'Unable to obtain jenkins_plugins table.');

report = '';
foreach longName (keys(plugins))
{
  res = query_scratchpad("SELECT version FROM jenkins_plugins WHERE longName = '" + longName +"';");
  if (empty_or_null(res)) continue;
  if(ver_compare(ver:res[0]['version'], fix:plugins[longName]) < 0)
  {
    report += '\nName: ' + longName;
    report += '\nVersion: ' + res[0]['version'];
    report += '\nFix: ' + plugins[longName];
  }
}

if (empty_or_null(report)) exit(0, 'There are no vulnerable versions of Jenkins plugins installed.');

security_report_v4(severity:SECURITY_WARNING, extra:report, port:0);